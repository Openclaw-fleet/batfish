#!/usr/bin/env python3
"""Run a lane-2 kernel/VyOS ground-truth corpus (JSONL) differentially against
(a) the Batfish translation (snapshots <prefix>-{new,est,nat}) and (b) the independent reference evaluator.

usage: run_corpus.py <corpus.jsonl> <render_dir> <snap_prefix> [--tcp-loose 0|1|both|config] [--out f.json]
JSONL fields: gateway, iif ("ethN"|"local"), src, dst, proto, sport, dport, icmp_type, tcp_flags, ct_state,
              verdict, optional oif/fib_oif, snat_src, egress ("src->dst" as seen leaving the box), sha.
Rows with layer "nftables-guest" are guest-firewall rows for another harness; they are counted and skipped.
Every disagreement is reported; nothing is dropped silently.

Conntrack is an input, never inferred from config:
- ct_state "a|b" (kernel-defined, OBSERVED): evaluated under each candidate; a verdict is reported only when all
  candidates agree, else UNSUPPORTED. "close" is a tracked entry and evaluates as established.
- related: evaluated as established only when every state-matching rule on the gateway matches both established
  and related (then the two are indistinguishable to the filters); otherwise UNSUPPORTED.
- reply-direction packets addressed to the router's SNAT address: the kernel's reverse NAT (from the conntrack
  entry, reported by lane 2 as egress dst or "dnat-back->X") is applied before filtering, as nf_nat does in
  PREROUTING. The un-NAT target is taken from the row; it is state, not config.
- SNAT is compared for every forwarded accepted row, including rows where the kernel did NOT translate.
  The translation of an established packet is the connection's mapping, decided by its first (SYN) packet.
  INVALID packets have no ct entry, so nf_nat never sees them: model SNAT is none by construction (ref only).
"""
import argparse, collections, glob, ipaddress, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bfmeasure import session, measure, RESULTS, WORK
from vyos_ref2 import Ref
from corpus import bf_eval, bf_headers, resolve_auto_src, PERMIT

ap = argparse.ArgumentParser()
ap.add_argument("corpus"); ap.add_argument("render"); ap.add_argument("prefix")
ap.add_argument("--tcp-loose", default="both"); ap.add_argument("--out")
a = ap.parse_args()
loose = a.tcp_loose if a.tcp_loose in ("both", "config") else int(a.tcp_loose)
NORM = {"accept": "accept", "accepted": "accept", "forward": "accept", "forwarded": "accept", "deliver": "accept",
        "delivered": "accept", "pass": "accept", "drop": "deny", "dropped": "deny", "reject": "deny", "rejected": "deny",
        "deny": "deny", "denied": "deny", "noroute": "noroute", "no_route": "noroute"}


def norm_verdict(v):
    v = str(v).lower()
    if v.startswith("snat->") or v.startswith("dnat-back->"):
        return "accept", v.split("->", 1)[1]
    return NORM.get(v, "?" + v), None


def flags(tf):
    tf = (tf or "").upper().replace(",", "").replace("|", "").replace(" ", "")
    for w, l in (("SYN", "S"), ("ACK", "A"), ("FIN", "F"), ("RST", "R"), ("PSH", "P")):
        tf = tf.replace(w, l)
    return {"syn": "S" in tf, "ack": "A" in tf, "rst": "R" in tf, "fin": "F" in tf, "psh": "P" in tf}, set(tf) - set("SAFRP")


def egress(r):
    e = r.get("egress")
    return tuple(e.split("->")) if e and "->" in e else (None, None)


nodes = {}
for d in sorted(glob.glob(f"{a.render}/node*")):
    nd = os.path.basename(d)
    side = json.load(open(f"{WORK}/v2/sidecar-{a.prefix}-new/{nd}.json"))
    text = open(f"{d}/vyos-commands.sh").read()
    nodes[nd] = nodes[side.get("host", nd)] = {"nd": nd, "host": side.get("host"), "ifmap": side["ifmap"], "text": text}
bf = session("v2")
refs = {}
rows = [json.loads(l) for l in open(a.corpus) if l.strip()]
rep = collections.Counter(); mism = []; log = []; skipped = collections.Counter(); notes = []
by = collections.defaultdict(list)
for i, r in enumerate(rows):
    if r.get("layer") == "nftables-guest":
        skipped["nftables-guest (other harness)"] += 1; continue
    g = nodes.get(r["gateway"]) or next((v for k, v in nodes.items() if r["gateway"] in k), None)
    if g is None:
        mism.append({"row": i, "kind": "UNKNOWN_GATEWAY", **r}); continue
    if g["nd"] not in refs:
        refs[g["nd"]] = Ref(g["text"], loose)
    by[g["nd"]].append((i, r))


def related_reducible(ref):
    sts = [ru["state"] for ch in ref.m.chains.values() for ru in (ch.get("rules") or {}).values() if ru.get("state")]
    return all({"established", "related"} <= s for s in sts), len(sts)


def bf_oif(oif, inv):
    return inv.get(oif.split(".")[0]) if oif else None


def model_snat(ref, host, ifmap, f, oif):
    """(ref_snat, batfish_snat) for the connection that f belongs to, decided on its first SYN/new packet."""
    f0 = dict(f, ct="new", syn=f["proto"] == "tcp", ack=False, rst=False, fin=False, psh=False)
    p = dict(f0, src=ipaddress.ip_address(f0["src"]), dst=ipaddress.ip_address(f0["dst"]))
    rs, _ = ref.snat(p, oif)
    bf.set_snapshot(f"{a.prefix}-nat")
    fr = bf.q.traceroute(startLocation=f"@enter({host}[{ifmap[f['iif']]}.0])", headers=bf_headers(f0)).answer().frame()
    bsrc = None
    traces = [t for tr in fr["Traces"] for t in tr]
    disp = {str(t.disposition) for t in traces}
    if not traces or not disp <= PERMIT:  # a denied NAT trace must not pass as "untranslated"
        return rs, f"batfish-nat-trace-not-permitted:{sorted(disp)}"
    for t in traces:
        for h in t.hops:
            for st in h.steps:
                tf_ = getattr(st.detail, "transformedFlow", None)
                s = tf_.get("srcIp") if isinstance(tf_, dict) else getattr(tf_, "srcIp", None)
                if s is not None and s != f0["src"]:
                    bsrc = s
    return rs, bsrc


with measure(f"corpus {len(rows)} rows", log):
    for nd, items in by.items():
        g = nodes[nd]; ref = refs[nd]; host = g["host"]; ifmap = g["ifmap"]; inv = {v: k for k, v in ifmap.items()}
        red, nstate = related_reducible(ref)
        notes.append(f"{host}: {nstate} state-matching rules; related==established for filters: {red}")
        sp = sorted(n for n, ch in ref.m.chains.items() for ru in (ch.get("rules") or {}).values() if "source port" in ru)
        notes.append(f"{host}: chains with source-port matches (sport stand-in is neutral elsewhere): {sorted(set(sp))}")
        for i, r in items:
            proto = str(r["proto"]).lower()
            fl, other = flags(r.get("tcp_flags")) if proto == "tcp" else ({k: False for k in ("syn", "ack", "rst", "fin", "psh")}, set())
            kv, unnat = norm_verdict(r["verdict"])
            esrc, edst = egress(r)
            # rows without sport (router-originated sockets): kernel picks an ephemeral port; 40000 stands in.
            # Neutral only if no chain the row can traverse matches on source port (reported per gateway in notes).
            sport = int(r["sport"]) if r.get("sport") is not None else (40000 if proto in ("tcp", "udp") else 0)
            f = {"iif": r["iif"], "src": r.get("src") or "AUTO", "dst": r["dst"], "proto": proto,
                 "sport": sport, "dport": int(r.get("dport") or 0), "row": i, **fl}
            if proto == "icmp":  # gw renders no icmp type/code match (checked), so code is verdict-neutral
                f["icmp_type"] = int(r.get("icmp_type") if r.get("icmp_type") is not None else 8)
                f["icmp_code"] = 4 if "frag" in r.get("id", "") else 0
            f = resolve_auto_src(ref.m, f, ref)
            cands = [c.strip().lower() for c in (r.get("ct_state") or "auto").split("|")]
            res = {"row": i, "id": r.get("id"), "gateway": host, "class": r.get("class"), "ct_state": r.get("ct_state"),
                   "tcp_flags": r.get("tcp_flags"), "kernel": kv, "kernel_result": r.get("result")}
            # reverse NAT from the conntrack entry (reply direction to the router's SNAT address)
            if f["iif"] != "local" and ipaddress.ip_address(f["dst"]) in ref.local and set(cands) & {"established", "related", "close"}:
                tgt = unnat or (edst if edst and edst != f["dst"] else None)
                if tgt:
                    res["unnat_dst"] = f"{f['dst']}->{tgt} (from ct entry)"; f["dst"] = tgt
            res["flow"] = {k: f.get(k) for k in ("iif", "src", "dst", "proto", "sport", "dport", "syn", "ack", "rst", "fin", "psh", "icmp_type")}
            if other:
                res.update(kind="UNSUPPORTED (explicit, not a pass)", why=f"tcp flags {''.join(sorted(other))} not modeled")
                mism.append(res); rep["unsupported"] += 1; continue
            outs = []
            for c in cands:
                c = {"close": "established"}.get(c, c)
                why_red = ""
                if c == "related":
                    if not red:
                        outs.append(("unsupported", "related with state rules not covering both est+rel", "unsupported", None)); continue
                    c, why_red = "established", " [related evaluated as established: every state rule matches both]"
                fc = dict(f, ct=c)
                rv, why, _ = ref.verdict(fc)
                if rv == "unsupported":
                    bv, boif = "unsupported", None
                else:
                    bf.set_snapshot(f"{a.prefix}-{'est' if c == 'established' else 'new'}")
                    bv, boif, disp, _ = bf_eval(bf, host, ifmap, dict(fc, ct="new" if c == "auto" else c))
                outs.append((rv, why + why_red, bv, bf_oif(boif, inv)))
            rvs = {o[0] for o in outs}; bvs = {o[2] for o in outs}
            if len(outs) > 1 and (len(rvs) > 1 or len(bvs) > 1):
                rv, why, bv, boif = "unsupported", f"ct-ambiguous {cands}: candidates disagree {outs}", "unsupported", None
            else:
                rv, why, bv, boif = outs[0]
                if len(outs) > 1:
                    why += f" [same verdict under ct {cands}]"
            res.update(ref=rv, ref_why=why, batfish=bv)
            rep[f"kernel={kv}|ref={rv}|batfish={bv}"] += 1
            if rv == "unsupported" or bv == "unsupported":
                res["kind"] = "UNSUPPORTED (explicit, not a pass)"; mism.append(res); continue
            if kv != bv or kv != rv:
                res["kind"] = "MISMATCH"; mism.append(res); continue
            if kv != "accept":
                continue
            # egress interface (FIB): kernel vs ref vs Batfish
            dst_ip = ipaddress.ip_address(f["dst"])
            if dst_ip in ref.local:
                moif = "local"
            else:
                rt = ref.route(dst_ip); moif = rt[1] if rt else None
            koif = r.get("oif") or r.get("fib_oif")
            if koif:
                ok = koif == moif and (boif in (None, moif) or moif == "local")
                rep[f"oif|{'agree' if ok else 'DISAGREE'}"] += 1
                if not ok:
                    mism.append({**res, "kind": "OIF_MISMATCH", "kernel_oif": koif, "ref_oif": moif, "batfish_oif": boif})
            if f["iif"] == "local" or moif == "local" or "unnat_dst" in res:
                continue
            # SNAT: kernel (snat_src, else egress src) vs model, for every forwarded accepted packet
            ksnat = r.get("snat_src") or (esrc if esrc and esrc != f["src"] else None)
            if not (r.get("snat_src") or esrc):
                rep["snat|no kernel egress record"] += 1; continue
            if len(cands) > 1:
                rep["snat|ct-ambiguous (not compared)"] += 1
                notes.append(f"{r.get('id')}: SNAT not compared, ct {cands} ambiguous; kernel snat={ksnat}"); continue
            if cands[0] == "invalid":
                ok = ksnat is None
                rep[f"snat-invalid(no ct, ref only)|{'agree' if ok else 'DISAGREE'}"] += 1
                if not ok:
                    mism.append({**res, "kind": "SNAT_MISMATCH", "kernel_snat": ksnat, "ref_snat": None, "batfish_snat": "n/a"})
                continue
            rs, bs = model_snat(ref, host, ifmap, f, moif)
            ok = (ksnat == rs == bs)
            rep[f"snat|{'agree' if ok else 'DISAGREE'}"] += 1
            res.update(kernel_snat=ksnat, ref_snat=rs, batfish_snat=bs)
            if not ok:
                mism.append({**res, "kind": "SNAT_MISMATCH"})
            else:
                rep[f"snat-agree|{'translated' if ksnat else 'untranslated'}"] += 1
out = {"corpus": a.corpus, "rows": len(rows), "skipped": dict(skipped), "tcp_loose": loose, "notes": notes,
       "summary": dict(rep), "n_mismatch": sum(1 for m in mism if m.get("kind") == "MISMATCH"),
       "n_snat_mismatch": sum(1 for m in mism if m.get("kind") == "SNAT_MISMATCH"),
       "n_oif_mismatch": sum(1 for m in mism if m.get("kind") == "OIF_MISMATCH"),
       "n_unsupported": sum(1 for m in mism if str(m.get("kind", "")).startswith("UNSUP")), "items": mism, "timings": log}
json.dump(out, open(a.out or f"{RESULTS}/corpus-{os.path.basename(a.corpus)}.json", "w"), indent=1, default=str)
print(json.dumps({k: v for k, v in out.items() if k != "items"}, indent=1, default=str))
