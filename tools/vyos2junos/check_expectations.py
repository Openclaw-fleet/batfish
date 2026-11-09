#!/usr/bin/env python3
"""Evaluate expectations.yml against translated gateways with Batfish.

usage: check_expectations.py <render_dir> <expectations.yml> <snap_prefix> [--decisions k=v,...] [--out results.json]

Builds snapshot <prefix>-chk = <prefix>-new configs + CHK_* filters (unapplied; analysis only), then:
  * filterLineReachability over CHK_* -> reachable permit/deny lines decide each check
  * searchFilters on failing CHK filters -> concrete witness flow
Result per assertion: PASS | FAIL | UNSUPPORTED | DECISION-PENDING (+ which branch the config satisfies).
"""
import argparse, collections, glob, ipaddress, json, os, shutil, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yaml
import hset as H
from hset import Cond, ANY
from vyos2junos import Gateway, Emitter, emit
from bfmeasure import session, measure, RESULTS, WORK
from pybatfish.datamodel.flow import HeaderConstraints

ap = argparse.ArgumentParser()
ap.add_argument("render"); ap.add_argument("expect"); ap.add_argument("prefix")
ap.add_argument("--decisions", default=""); ap.add_argument("--out")
ap.add_argument("--only", default="")
a = ap.parse_args()
E = yaml.safe_load(open(a.expect))
decisions = {k: v["status"] for k, v in E["decisions"].items()}
for kv in filter(None, a.decisions.split(",")):
    k, v = kv.split("="); decisions[k] = v

NON_PUBLIC = H.ipset(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                      "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"])
PUBLIC = H.minus(None, NON_PUBLIC)
NEW_SCOPES = [Cond(proto=frozenset({"tcp"}), flags="SYNONLY"), Cond(proto=frozenset({"udp"})), Cond(proto=frozenset({"icmp"}))]
subnet = {z: H.ipset([s]) for z, s in E["zone_subnets"].items()}


def spec_cond(s, default_src, default_dst):
    def ips(v, dflt):
        if v is None:
            return dflt
        if "__EMPTY__" in v:
            return ()
        return H.ipset(v)
    c = Cond(src=ips(s["src"], default_src), dst=ips(s["dst"], default_dst))
    if s.get("protocol"):
        if s["protocol"] not in ("tcp", "udp", "icmp"):
            return None
        c.proto = frozenset([s["protocol"]])
    if s.get("dst_ports"):
        c.dport = H.portset(s["dst_ports"])
    if s.get("src_ports"):
        c.sport = H.portset(s["src_ports"])
    return c & ANY


class Checks:
    def __init__(self):
        self.filters = {}   # name -> list of (Cond, action, origin)
        self.meta = {}      # name -> dict

    def add(self, meta, terms):
        terms = [(c, v, o) for c, v, o in terms if c is not None]
        if not any(v == "accept" for _, v, _ in terms) and meta["mode"] != "deny-lines":
            return  # nothing can be permitted -> trivially passes; record as checked
        if meta["mode"] == "deny-lines" and not any(v != "accept" for _, v, _ in terms):
            return
        n = f"CHK_{len(self.filters):06d}"
        # deny-lines: exclusions and out-of-scope are 'accept' so searchFilters(action=deny) yields a real witness
        self.filters[n] = terms + [(ANY, "accept" if meta["mode"] == "deny-lines" else "drop", "chk:end")]
        self.meta[n] = meta


def restrict(terms, scope):
    out = []
    for c, v, o in terms:
        cc = c & scope
        if cc is not None:
            out.append((cc, v, o))
    return out


t_build = time.time()
CK = Checks()
coverage = collections.Counter()
gws = {}
for d in sorted(glob.glob(f"{a.render}/node*")):
    nd = os.path.basename(d)
    gw = Gateway(open(f"{d}/vyos-commands.sh").read(), "new")
    gwn = Gateway(open(f"{d}/vyos-commands.sh").read(), "new")
    host = gw.m.host
    gws[nd] = gw
    members = collections.defaultdict(list)
    for i, z in gw.zone_of.items():
        if i in gw.enabled:
            members[z].append(i)
    in_terms = {i: gw.in_terms(i) for i in gw.enabled}
    unsup = {i: [(c, "accept", f"UNSUP:{o}|{why}") for c, why, o in gw.unsup_regions.get(i, [])] for i in gw.enabled}
    gwips = gw.local
    not_special = H.minus(None, gw.special_dst)

    def dst_of(zone_or_local, internet=False, exclude=None):
        # Full target-zone subnet, wherever it is routed: cross-node traffic is filtered on this gateway
        # by jumps from X-to-wan / X-to-xsite into the destination-zone chain. Paths that leave without
        # passing a target-zone chain are classified TRANSIT at evaluation time (never silently passed).
        if internet or zone_or_local == "wan":
            return H.minus(PUBLIC, exclude) if exclude else PUBLIC
        if zone_or_local == "local":
            return gwips
        if zone_or_local not in subnet:
            return None
        return H.inter(H.minus(subnet[zone_or_local], gwips), not_special) or None

    def src_of(zone, wan_sources):
        if zone == "wan":
            return PUBLIC if wan_sources == "public" else H.minus(None, H.union(gwips, H.ipset(["0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"])))
        return H.minus(subnet[zone], gwips)

    for A in E["assertions"]:
        if a.only and A["id"] not in a.only.split(","):
            continue
        k = A["kind"]
        if k in ("no-new-flows", "decision"):
            for fz in A["from_zones"]:
                for iif in members.get(fz, []):
                    tzs = ["__internet__"] if A.get("to_internet") else A["to_zones"]
                    for tz in tzs:
                        dst = dst_of(tz, internet=tz == "__internet__", exclude=H.ipset(A.get("exclude_dst", [])) if A.get("exclude_dst") else None)
                        if not dst:
                            continue
                        src = src_of(fz, A.get("wan_sources", "any"))
                        for sc in NEW_SCOPES:
                            if A.get("protocols") and next(iter(sc.proto)) not in A["protocols"]:
                                continue
                            scope = Cond(src=src, dst=dst) & sc
                            if A.get("dst_ports"):
                                scope = scope & Cond(dport=H.portset(A["dst_ports"])) if scope else None
                            if scope is None:
                                continue
                            meta = {"assertion": A["id"], "gw": host, "node": nd, "iif": iif, "from": fz, "to": tz,
                                    "proto": next(iter(sc.proto)), "mode": "permit-lines"}
                            CK.add(meta, restrict(in_terms[iif], scope))
                            CK.add({**meta, "mode": "unsup"}, restrict(unsup[iif], scope))
                            coverage[(A["id"], "scopes")] += 1
        elif k == "allowed-subset-of-policy":
            for fz in A["from_zones"]:
                for iif in members.get(fz, []):
                    for tz in A["to_zones"]:
                        if tz == fz:
                            continue
                        dst = dst_of(tz)
                        if not dst:
                            continue
                        src = src_of(fz, A.get("wan_sources", "any"))
                        pair = E["pairs"].get(f"{fz}->{tz}")
                        for sc in NEW_SCOPES:
                            scope = Cond(src=src, dst=dst) & sc
                            if scope is None:
                                continue
                            act = restrict(in_terms[iif], scope)
                            terms = []
                            if pair is None:
                                terms = act  # no policy: everything permitted is unexpected
                            elif pair["default_action"] == "accept":
                                continue
                            else:
                                comp_done = False
                                for r in pair["rules"] + [{"policy_rule": 10**9, "state_only": True}]:
                                    if not comp_done and r["policy_rule"] > 902:
                                        comp_done = True
                                        if sc.proto == {"icmp"} and not pair.get("suppress_icmp_companion"):
                                            terms.append((scope, "drop", f"expected:{fz}->{tz}:902-companion(decision)"))
                                    if r["state_only"]:
                                        continue
                                    ec = spec_cond(r, src, dst)
                                    if ec is None:
                                        continue
                                    ec = ec & scope
                                    if ec is None:
                                        continue
                                    if r["action"] == "accept":
                                        terms.append((ec, "drop", f"expected:{fz}->{tz}:{r['policy_rule']}"))
                                    else:
                                        terms += restrict(act, ec)
                                terms += act
                            meta = {"assertion": A["id"], "gw": host, "node": nd, "iif": iif, "from": fz, "to": tz,
                                    "proto": next(iter(sc.proto)), "mode": "permit-lines"}
                            CK.add(meta, terms)
                            CK.add({**meta, "mode": "unsup"}, restrict(unsup[iif], scope))
                            coverage[(A["id"], "scopes")] += 1
        elif k == "policy-rules-permitted":
            for key, pair in E["pairs"].items():
                fz, tz = pair["from"], pair["to"]
                # destination zone need not be local: cross-node destinations are filtered here via
                # X-to-wan/X-to-xsite jumps into the X-to-<tz> chain
                if fz == "wan" or not members.get(fz):
                    continue
                iif = members[fz][0]
                src = src_of(fz, "any"); dst = dst_of(tz)
                if not dst:
                    continue
                earlier_drops = []
                for r in pair["rules"]:
                    if r["state_only"]:
                        continue
                    ec = spec_cond(r, src, dst)
                    if ec is None:
                        continue
                    if r["action"] != "accept":
                        earlier_drops.append(ec); continue
                    for sc in NEW_SCOPES:
                        e = ec & sc
                        e = e & Cond(src=src, dst=dst) if e is not None else None  # within this gateway zone scope
                        if e is None:
                            continue
                        terms = [(d & e, "accept", "expected-drop-earlier") for d in earlier_drops if (d & e) is not None]
                        # kernel K1 (martian/local source) drops are not policy-rule denials: excluded, documented
                        terms += [(c, "accept", "excluded:" + o) if o.startswith("kernel:K1") else (c, v, o)
                                  for c, v, o in restrict(in_terms[iif], e)]
                        meta = {"assertion": A["id"] if (A := next(x for x in E["assertions"] if x["kind"] == "policy-rules-permitted")) else "",
                                "gw": host, "node": nd, "iif": iif, "from": fz, "to": tz, "policy_rule": r["policy_rule"],
                                "description": r["description"], "proto": next(iter(sc.proto)), "mode": "deny-lines"}
                        CK.add(meta, terms)
                        CK.add({**meta, "mode": "unsup"}, restrict(unsup[iif], e))
                        coverage[("M1", "rules")] += 1
        elif k == "nonsyn-tcp-scope":
            keep = lambda f, t: (not A["remove_cross_node_ack_rules"]) or f in ("pkicore", "pkidmz") or t in ("pkicore", "pkidmz") or (f == "backup" and t == "wan")
            for fz, ifs in members.items():
                for iif in ifs:
                    for tz in list(members) + ["local"]:
                        if tz == fz:
                            continue
                        dst = dst_of(tz)
                        if not dst:
                            continue
                        scope = Cond(src=src_of(fz, "any"), dst=dst, proto=frozenset({"tcp"}), flags="ACKNOSYN")
                        meta = {"assertion": A["id"], "gw": host, "node": nd, "iif": iif, "from": fz, "to": tz, "proto": "tcp",
                                "mode": "permit-lines-901", "documented": keep(fz, tz)}
                        CK.add(meta, [(c, v, o) for c, v, o in restrict(in_terms[iif], scope)])
                        CK.add({**meta, "mode": "unsup"}, restrict(unsup[iif], scope))
                        coverage[(A["id"], "scopes")] += 1
t_build = time.time() - t_build
print("check filters", len(CK.filters), "build_s", round(t_build, 1), flush=True)

# ---- write chk snapshot: new-class configs + CHK filters appended per node ----
snap = f"{WORK}/snap/{a.prefix}-chk"
shutil.rmtree(snap, ignore_errors=True)
shutil.copytree(f"{WORK}/snap/{a.prefix}-new", snap)
by_node = collections.defaultdict(list)
for n, m in CK.meta.items():
    by_node[m["node"]].append(n)
term_origin = {}
nlines = 0
for nd, names in by_node.items():
    e = Emitter()
    for n in names:
        for k_, (c, v, o) in enumerate(CK.filters[n]):
            e.term(n, k_, c, v, o)
    term_origin.update(e.terms)
    with open(f"{snap}/configs/{nd}.cfg", "a") as f:
        f.write("\n".join(e.L) + "\n")
    nlines += len(e.L)
print("chk lines", nlines, flush=True)

bf = session("v2")
log = []
with measure("init chk snapshot", log):
    bf.init_snapshot(snap, name=f"{a.prefix}-chk", overwrite=True)
bf.set_snapshot(f"{a.prefix}-chk")
iss = bf.q.initIssues().answer().frame()
with measure("filterLineReachability CHK_*", log):
    flr = bf.q.filterLineReachability(filters="/^CHK_/").answer().frame()
# Sources entries are "node: F1, F2, ..." (Batfish groups identical filters on a node into one entry)
unreach_idx = collections.defaultdict(set)
for _, r in flr.iterrows():
    for s in r["Sources"]:
        node, _, fl = str(s).partition(": ")
        for fn in fl.split(", "):
            unreach_idx[f"{node}: {fn}"].add(str(r["Unreachable_Line"]).split()[0] if str(r["Unreachable_Line"]) else "")
# Batfish line text for Junos terms starts with the term name; use it as key
results = collections.defaultdict(lambda: {"violations": [], "unsupported": [], "checks": 0, "branch_hits": [], "transit": []})
import re


def is_transit(o, tz):
    """Permit that leaves this gateway without passing any chain for the target zone: forwarded to the
    owning gateway, which enforces wan->tz there (assumption K4: transit arrives on the owner's wan/xsite
    interface with the original source address)."""
    if tz in ("local", "wan", "__internet__"):
        return False
    m_ = re.search(r"zone:(?:([\w]+)->([\w]+)|([\w]+):(?:intra|default))", o)
    if not m_:
        return False
    zo = m_.group(2) or m_.group(3)
    return zo != tz and f"-to-{tz}:" not in o
witness_needed = []
for n, m in CK.meta.items():
    key = f"{m['gw']}: {n}"
    un = unreach_idx.get(key, set())
    res = results[m["assertion"]]
    res["checks"] += 1
    for k_, (c, v, o) in enumerate(CK.filters[n][:-1]):
        tn = f"t{k_:05d}"
        reachable = tn not in un
        if not reachable:
            continue
        if m["mode"] == "unsup" and v == "accept":
            res["unsupported"].append({**{x: m[x] for x in ("gw", "from", "to", "proto")}, "region": o}); break
        if m["mode"] in ("permit-lines",) and v == "accept" and is_transit(o, m["to"]):
            res["transit"].append({**{x: m.get(x) for x in ("gw", "iif", "from", "to", "proto")}, "permitted_by": o}); continue
        if m["mode"] in ("permit-lines",) and v == "accept":
            res["violations"].append({**{x: m.get(x) for x in ("gw", "iif", "from", "to", "proto")}, "permitted_by": o, "filter": n, "term": tn})
            witness_needed.append((n, m, tn))
        if m["mode"] == "permit-lines-901" and v == "accept" and o.split(">")[-1].endswith(":901"):
            res["violations" if not m["documented"] else "branch_hits"].append(
                {**{x: m.get(x) for x in ("gw", "from", "to")}, "permitted_by": o, "documented": m["documented"], "filter": n})
        if m["mode"] == "deny-lines" and v != "accept":
            res["violations"].append({**{x: m.get(x) for x in ("gw", "from", "to", "proto", "policy_rule", "description")},
                                      "denied_by": o, "filter": n, "term": tn})
            witness_needed.append((n, m, tn))
            break
# witnesses for a bounded number of failures
seen = set()
with measure("searchFilters witnesses", log):
    for n, m, tn in witness_needed:
        if n in seen or len(seen) >= 60:
            continue
        seen.add(n)
        act = "permit" if m["mode"] == "permit-lines" else "deny"
        r = bf.q.searchFilters(nodes=m["gw"], filters=n, action=act).answer().frame()
        if len(r):
            f = r["Flow"].iloc[0]
            for v in results[m["assertion"]]["violations"]:
                if v.get("filter") == n and "witness" not in v:
                    v["witness"] = f"{f.srcIp}->{f.dstIp} {f.ipProtocol} dport={f.dstPort}" + (f" flags=SYN{f.tcpFlagsSyn}ACK{f.tcpFlagsAck}" if str(f.ipProtocol) == "TCP" else "")
                    v["matched_line"] = str(r["Line_Content"].iloc[0])[:160] if "Line_Content" in r else ""

summary = {}
for A in E["assertions"]:
    if a.only and A["id"] not in a.only.split(","):
        continue
    r = results[A["id"]]
    if A["kind"] == "decision":
        allowed = bool(r["violations"])
        dec = decisions.get(A["decision"], "pending")
        branch = "allowed" if allowed else "forbidden"
        status = "UNSUPPORTED" if r["unsupported"] else ("DECISION-PENDING" if dec == "pending" else ("PASS" if dec == branch else "FAIL"))
        summary[A["id"]] = {"status": status, "config_satisfies_branch": branch, "decision": dec,
                            "evidence_count": len(r["violations"]), "evidence": r["violations"][:12], "n_transit_deferred": len(r["transit"]), "unsupported": r["unsupported"][:10], "checks": r["checks"]}
    elif A["kind"] == "nonsyn-tcp-scope":
        status = "FAIL" if r["violations"] else ("UNSUPPORTED" if r["unsupported"] else "PASS")
        doc_pairs = sorted({(x["gw"], x["from"], x["to"]) for x in r["branch_hits"]})
        summary[A["id"]] = {"status": status, "undocumented_nonsyn_paths": r["violations"][:20], "n_undocumented": len(r["violations"]),
                            "documented_nonsyn_paths": len(doc_pairs),
                            "documented_examples": [f"{g}:{f}->{t}" for g, f, t in doc_pairs[:24]], "checks": r["checks"],
                            "n_unsupported": len(r["unsupported"]), "unsupported": r["unsupported"][:10]}
    else:
        status = "FAIL" if r["violations"] else ("UNSUPPORTED" if r["unsupported"] else "PASS")
        summary[A["id"]] = {"status": status, "n_violations": len(r["violations"]), "violations": r["violations"][:400],
                            "n_transit_deferred": len(r["transit"]), "transit_deferred": r["transit"][:60],
                            "n_unsupported": len(r["unsupported"]), "unsupported": r["unsupported"][:10], "checks": r["checks"]}
    print(A["id"], summary[A["id"]]["status"], {k: v for k, v in summary[A["id"]].items() if k in ("n_violations", "n_unsupported", "n_transit_deferred", "config_satisfies_branch", "n_undocumented", "documented_nonsyn_paths", "checks", "evidence_count")}, flush=True)
out = {"expectations": a.expect, "generated_from": E["generated_from"], "decisions": decisions, "summary": summary,
       "timings": log + [{"step": "build check filters (python)", "wall_s": round(t_build, 1)}],
       "n_check_filters": len(CK.filters), "chk_lines": nlines, "init_issues": len(iss)}
json.dump(out, open(a.out or f"{RESULTS}/check-{a.prefix}.json", "w"), indent=1, default=str)
