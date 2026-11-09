#!/usr/bin/env python3
"""v2: exact, analysis-only compilation of a rendered ProxMoxSDN VyOS gateway into Junos
stateless interface filters for Batfish.

Semantics source: vyos-1x data/templates/firewall/nftables.j2 + nftables-zone.j2 and
interface-definitions (rev dbde15e2, 2026-10-17):
  forward hook : VYOS_FORWARD_filter (prio 0; accept continues to next base chain)
                 -> VYOS_ZONE_FORWARD (prio 1): oifname Z jump VZONE_Z:
                    iifname Z return | iifname F jump NAME_<F-to-Z>; return | default-action
  input hook   : VYOS_ZONE_LOCAL -> VZONE_<local>_IN: iifname F jump NAME_<F-to-local>; return | default
  output hook  : VYOS_ZONE_OUTPUT -> VZONE_<local>_OUT: oifname Z jump NAME_<local-to-Z>; return | default
  named chain default-action: CLI default 'drop' (include/firewall/default-action.xml.i)
Kernel assumptions (stated, for lane-2 validation): K1 accept_local=0 (packets arriving with a
local source are dropped before the filter); K2 rp_filter=0; K3 nf_conntrack_tcp_loose=0 (rendered).

Snapshot classes (one Junos config per gateway per class):
  new : conntrack state NEW or INVALID (state established/related never match; TCP flags real,
        so SYN-only hits rule 900 and non-SYN hits rule 901). Input+output filters, no NAT.
  est : conntrack state ESTABLISHED (state rules match). Input+output filters, no NAT.
  nat : 'new' input filters + source NAT rule-sets (VyOS rule order), no output filters
        (Batfish applies output filters after NAT; the gateway's pool IPs are its own addresses).
Anything verdict-relevant that cannot be encoded exactly goes into UNSUP_<if> filters (permit =
region whose verdict is not modelled) and the sidecar; checks touching those regions report
UNSUPPORTED instead of passing.
"""
import os, argparse, hashlib, ipaddress, json, sys
from collections import defaultdict, Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vyosmodel import load_commands, Model
import hset as H
from hset import Cond, ANY

DENY = {"drop", "reject"}
SPECIAL_DST = H.ipset(["0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"])
MARTIAN_SRC = H.ipset(["0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"])


class Unsup(Exception):
    pass


def vclass(v):
    return "accept" if v == "accept" else "deny"


class Gateway:
    def __init__(self, text, cls):
        self.cls = cls
        self.m = Model(load_commands(text))
        m = self.m
        self.stats = Counter()
        self.unsup_regions = defaultdict(list)   # iface -> [(Cond, reason, origin)]
        self.global_unsup = list(m.unsupported)
        # apply documented CLI default for named chains, but only for referenced chains
        for name, ch in m.chains.items():
            if ch["default"] is None and name != "__FWD__":
                ch["default"] = "drop"; self.stats["chain_default_cli_drop"] += 1
        self.global_unsup = [u for u in self.global_unsup if "no default-action (refusing" not in u[1]]
        if "__FWD__" in m.chains and m.chains["__FWD__"]["default"] is None:
            m.chains["__FWD__"]["default"] = "accept"  # forward filter base-chain default (default-action-base-chains: accept)
        self.zone_of = {}
        for z, c in m.zones.items():
            if c["local"]:
                continue
            for i in c["members"]:
                if i in self.zone_of:
                    self.global_unsup.append((f"interface {i}", "member of two zones"))
                self.zone_of[i] = z
        self.local_zone = next((z for z, c in m.zones.items() if c["local"]), None)
        self.enabled = [e for e, i in m.ifaces.items() if not i["disable"]]
        self.local = H.ipset([str(ipaddress.ip_interface(a).ip) for e in self.enabled for a in m.ifaces[e]["addr"]])
        bc = []
        for e in self.enabled:
            for a in m.ifaces[e]["addr"]:
                n = ipaddress.ip_interface(a).network
                if n.prefixlen < 31:
                    bc += [str(n.network_address), str(n.broadcast_address)]
        self.special_dst = H.union(SPECIAL_DST, H.ipset(bc + ["255.255.255.255"]))
        self.regions = self._regions()

    # ---------- routing: exact LPM partition of destination space by egress ----------
    def _regions(self):
        rib = self.m.rib()
        for (pfx, kind, arg) in self.m.routes:
            if kind == "next-hop" and not any(ipaddress.ip_address(arg) in n for n, _ in self.m.connected()):
                self.stats["static_route_unresolvable_inactive"] += 1
        entries = sorted(rib, key=lambda r: -r[0].prefixlen)
        covered = ()
        reg = defaultdict(tuple)
        for n, e, nh in entries:
            s = H.minus(H.ipset([n]), covered)
            covered = H.union(covered, H.ipset([n]))
            key = e if e is not None else "__blackhole__"
            reg[key] = H.union(reg[key], s) if reg[key] else s
        return dict(reg)

    # ---------- rule -> Cond ----------
    def rule_cond(self, r):
        """Returns (Cond|None, conditional_reason|None). None cond => never matches in this class."""
        if r.get("disable"):
            return None, None
        if r.get("unsupported"):
            raise Unsup("rule field(s): " + ", ".join(r["unsupported"]))
        st = r.get("state")
        if st:
            if not st <= {"established", "related"}:
                raise Unsup("state " + ",".join(sorted(st)))
            if self.cls in ("new", "nat"):
                return None, None
            # est: an established packet matches 'established' (related packets: unsupported class)
        c = Cond()
        if "protocol" in r:
            if r["protocol"] not in ("tcp", "udp", "icmp"):
                raise Unsup("protocol " + r["protocol"])
            c.proto = frozenset([r["protocol"]])
        for side in ("source", "destination"):
            f = "src" if side == "source" else "dst"
            if f"{side} address" in r:
                setattr(c, f, H.inter(getattr(c, f), H.ipset([r[f"{side} address"]])))
            for g in ("address-group", "network-group"):
                if f"{side} group {g}" in r:
                    setattr(c, f, H.inter(getattr(c, f), H.ipset(self.m.groups[g][r[f"{side} group {g}"]])))
            if f"{side} port" in r:
                setattr(c, "dport" if side == "destination" else "sport", H.portset(r[f"{side} port"]))
        if (c.dport is not None or c.sport is not None) and c.proto is None:
            raise Unsup("port match without protocol")
        if r.get("tcpflags"):
            if r["tcpflags"] != {"syn", "not ack"}:
                raise Unsup("tcp flags " + ",".join(sorted(r["tcpflags"])))
            c.flags = "SYNONLY"
        cond_reason = None
        if r.get("limit"):
            cond_reason = "limit rate"
        if "source mac-address" in r:
            cond_reason = (cond_reason + "+" if cond_reason else "") + "source mac-address"
        c2 = c & ANY
        return c2, cond_reason

    # ---------- chain compilation (first-match, jumps inlined) ----------
    def chain(self, name, ctx, origin, iface, depth=0):
        """Returns list of (Cond, verdict, origin). Verdict accept/drop/reject or 'return'."""
        if depth > 8:
            raise Unsup("jump depth")
        ch = self.m.chains[name]
        out = []
        conditional = []
        for num in sorted(ch["rules"]):
            r = ch["rules"][num]
            o = f"{origin}>{name}:{num}" if origin else f"{name}:{num}"
            try:
                c, cond_reason = self.rule_cond(r)
            except Unsup as e:
                # whole rule region unknown -> UNSUP region (rule's own match space, over-approximated by ctx)
                self.unsup_regions[iface].append((ctx, f"{o}: {e}", o)); self.stats["rule_unsupported_region"] += 1
                continue
            if c is None:
                self.stats["rule_never_matches_in_class"] += 1
                continue
            c = ctx & c
            if c is None:
                self.stats["rule_empty_in_context"] += 1
                continue
            a = r.get("action")
            if a == "jump":
                sub = self.chain(r["jump-target"], c, o, iface, depth + 1)
                if any(v == "return" for _, v, _ in sub):
                    self.unsup_regions[iface].append((c, f"{o}: return inside jump target", o))
                    sub = [(cc, v, oo) for cc, v, oo in sub if v != "return"]
                out += sub
                self.stats["jump_inlined"] += 1
            elif a in ("accept", "drop", "reject", "return"):
                if cond_reason:
                    conditional.append((len(out), c, a, o, cond_reason))
                out.append((c, a, o))
            else:
                self.unsup_regions[iface].append((c, f"{o}: action {a}", o))
        d = ch["default"]
        if d not in ("accept", "drop", "reject", "return"):
            self.unsup_regions[iface].append((ctx, f"{name}: default-action {d}", name))
            d = "drop"
        out.append((ctx, d, f"{origin}>{name}:default" if origin else f"{name}:default"))
        # neutrality of conditional (limit/mac) rules: verdict must not depend on whether they match
        for pos, c, a, o, why in conditional:
            # exact-or-larger non-neutral region: union of c & (later term whose verdict class differs).
            # Every packet whose fall-through verdict differs is matched by such a term, so fencing these
            # pieces is sound; the rest of c is verdict-neutral and modeled exactly.
            bad = []
            for cc, v, oo in out[pos + 1:]:
                m_ = c & cc
                if m_ is None:
                    continue
                if v == "return" or vclass(v) != vclass(a):
                    bad.append((m_, oo))
                elif m_.key() == c.key():
                    break  # a later same-class term covers the whole rule region: nothing falls further

            if not bad:
                self.stats[f"conditional_rule_neutral[{why}]"] += 1
            elif len(bad) > 64:
                self.stats[f"conditional_rule_UNSUP_region[{why}]"] += 1
                self.unsup_regions[iface].append((c, f"{o}: verdict depends on {why}", o))
            else:
                self.stats[f"conditional_rule_partial_UNSUP[{why}]"] += 1
                for b, oo in bad:
                    self.unsup_regions[iface].append((b, f"{o}: verdict depends on {why} (fall-through to {oo})", o))
        return out

    # ---------- per-interface filter construction ----------
    def zone_block(self, iif, ctx):
        """Forward verdict for packets entering iif (already restricted by ctx)."""
        zi = self.zone_of.get(iif)
        terms = []
        for oif, reg in sorted(self.regions.items()):
            rc = ctx & Cond(dst=reg)
            if rc is None:
                continue
            if oif == "__blackhole__":
                terms.append((rc, "drop", "route:blackhole")); continue
            zo = self.zone_of.get(oif)
            if zo is None:
                terms.append((rc, "accept", f"zone:none(oif={oif})")); continue
            if zi == zo:
                terms.append((rc, "accept", f"zone:{zo}:intra")); continue
            chname = self.m.zones[zo]["from"].get(zi) if zi else None
            if chname is None:
                terms.append((rc, self.m.zones[zo]["default"], f"zone:{zo}:default(from={zi})")); continue
            for c, v, o in self.chain(chname, rc, f"zone:{zi}->{zo}", iif):
                terms.append((c, "accept" if v == "return" else v, o))
        return terms

    def in_terms(self, iif):
        T = []
        # K1: martian / local source dropped by the kernel before netfilter forward/input
        T.append((Cond(src=H.union(self.local, MARTIAN_SRC)), "drop", "kernel:K1-martian-or-local-source"))
        # special destinations: broadcast/network/multicast/loopback -> unsupported region
        T.append((Cond(dst=self.special_dst), "drop", "UNSUP:special-destination"))
        self.unsup_regions[iif].append((Cond(dst=self.special_dst), "broadcast/network/multicast/loopback destination", "special-dst"))
        # local-in
        lctx = Cond(dst=self.local)
        zi = self.zone_of.get(iif)
        lz = self.local_zone
        if lz is None:
            T.append((lctx, "accept", "local:no-local-zone"))
        else:
            chname = self.m.zones[lz]["from"].get(zi) if zi else None
            if chname is None:
                T.append((lctx, self.m.zones[lz]["default"], f"local:{lz}:default(from={zi})"))
            else:
                for c, v, o in self.chain(chname, lctx, f"local:{zi}->{lz}", iif):
                    T.append((c, "accept" if v == "return" else v, o))
        # forward: VYOS_FORWARD_filter then zones (accept in prio-0 chain continues to prio-1 chain)
        fwd = Cond(dst=H.minus(None, H.union(self.local, self.special_dst)))
        if "__FWD__" in self.m.chains:
            entries = self.chain("__FWD__", fwd, "fwd", iif)
            for c, v, o in entries:
                if v == "accept":
                    T += [(cc, vv, f"{o}=>{oo}") for cc, vv, oo in self.zone_block(iif, c)]
                elif v == "return":
                    self.unsup_regions[iif].append((c, "return in forward base chain", o))
                else:
                    T.append((c, v, o))
        else:
            T += self.zone_block(iif, fwd)
        T.append((ANY, "drop", "noroute"))
        return T

    def out_terms(self, oif):
        """Router-originated traffic (src in local addresses, by K1) leaving oif."""
        lctx = Cond(src=self.local)
        T = []
        lz = self.local_zone
        zo = self.zone_of.get(oif)
        if lz is None:
            T.append((lctx, "accept", "localout:no-local-zone"))
        else:
            chname = self.m.zones[zo]["from"].get(lz) if zo else None
            if chname is None:
                T.append((lctx, self.m.zones[lz]["default"], f"localout:{lz}:default(to={zo})"))
            else:
                for c, v, o in self.chain(chname, lctx, f"localout:{lz}->{zo}", f"OUT:{oif}"):
                    T.append((c, "accept" if v == "return" else v, o))
        T.append((ANY, "accept", "forwarded"))
        return T


# ------------------------------- Junos emission -------------------------------
class Emitter:
    def __init__(self):
        self.L = []
        self.pl = {}
        self.terms = {}

    def plist(self, iv):
        k = hashlib.sha1(repr(iv).encode()).hexdigest()[:10]
        name = f"PL_{k}"
        if name not in self.pl:
            self.pl[name] = iv
            for c in H.cidrs(iv):
                self.L.append(f"set policy-options prefix-list {name} {c}")
        return name

    def term(self, filt, idx, c, action, origin):
        tn = f"t{idx:05d}"
        self.terms[f"{filt}/{tn}"] = {"origin": origin, "action": action, "cond": repr(c)}
        b = f"set firewall family inet filter {filt} term {tn}"
        if c.src is not None and c.src != H.FULL_IP:
            self.L.append(f"{b} from source-prefix-list {self.plist(c.src)}")
        if c.dst is not None and c.dst != H.FULL_IP:
            self.L.append(f"{b} from destination-prefix-list {self.plist(c.dst)}")
        if c.proto is not None:
            for p in sorted(c.proto):
                self.L.append(f"{b} from protocol {p}")
        for f, kw in (("dport", "destination-port"), ("sport", "source-port")):
            v = getattr(c, f)
            if v is not None and v != H.FULL_PORT:
                for a, z in v:
                    self.L.append(f"{b} from {kw} {a}" + (f"-{z}" if z != a else ""))
        if c.flags == "SYNONLY":
            self.L.append(f'{b} from tcp-flags "(syn & !ack)"')
        elif c.flags == "ACKNOSYN":
            self.L.append(f'{b} from tcp-flags "(!syn & ack)"')
        self.L.append(f"{b} then " + {"accept": "accept", "drop": "discard", "reject": "reject"}[action])


def emit(gw, cls):
    e = Emitter()
    m = gw.m
    e.L.append(f"set system host-name {m.host}")
    ifmap = {i: f"ge-0/0/{int(i[3:])}" for i in m.ifaces}
    for i, d in m.ifaces.items():
        j = ifmap[i]
        if d["disable"]:
            e.L.append(f"set interfaces {j} disable")
        for a in d["addr"]:
            e.L.append(f"set interfaces {j} unit 0 family inet address {a}")
    for p, kind, arg in m.routes:
        if kind == "next-hop":
            e.L.append(f"set routing-options static route {p} next-hop {arg}")
        elif kind == "interface":
            e.L.append(f"set routing-options static route {p} next-hop {ifmap[arg]}.0")
        else:
            e.L.append(f"set routing-options static route {p} discard")
    nterms = 0
    for i in gw.enabled:
        j = ifmap[i]
        f = "IN_" + j.replace("/", "_").replace("-", "_")
        for k, (c, v, o) in enumerate(gw.in_terms(i)):
            e.term(f, k, c, v, o); nterms += 1
        e.L.append(f"set interfaces {j} unit 0 family inet filter input {f}")
        if cls in ("new", "est"):
            g = "OUT_" + j.replace("/", "_").replace("-", "_")
            for k, (c, v, o) in enumerate(gw.out_terms(i)):
                e.term(g, k, c, v, o); nterms += 1
            e.L.append(f"set interfaces {j} unit 0 family inet filter output {g}")
    # unsupported regions, per ingress interface (and OUT:<if> for local-out)
    for key, regs in gw.unsup_regions.items():
        j = ifmap.get(key) or ifmap.get(key.split(":", 1)[-1])
        f = ("UNSUP_OUT_" if key.startswith("OUT:") else "UNSUP_") + j.replace("/", "_").replace("-", "_")
        for k, (c, why, o) in enumerate(regs):
            e.term(f, k, c, "accept", f"{o} | {why}")
        e.term(f, len(regs), ANY, "drop", "supported")
    if cls == "nat":
        nat_emit(gw, e, ifmap)
    return e, nterms, ifmap


def addrset(e, iv):
    k = "AS_" + hashlib.sha1(repr(iv).encode()).hexdigest()[:10]
    if k not in e.pl:
        e.pl[k] = iv
        for cc in H.cidrs(iv):
            an = "A_" + cc.replace(".", "_").replace("/", "_")
            if an not in e.pl:
                e.pl[an] = cc
                e.L.append(f"set security address-book global address {an} {cc}")
            e.L.append(f"set security address-book global address-set {k} address {an}")
    return k


def nat_emit(gw, e, ifmap):
    m = gw.m
    pools = set()
    for i in gw.enabled:
        j = ifmap[i]
        rules = [(n, r) for n, r in sorted(m.nat.items()) if not r.get("disable") and r.get("oif", i) == i]
        if not rules:
            continue
        rs = "snat_" + j.replace("/", "_").replace("-", "_")
        e.L.append(f"set security nat source rule-set {rs} from routing-instance default")
        e.L.append(f"set security nat source rule-set {rs} to interface {j}.0")
        for n, r in rules:
            b = f"set security nat source rule-set {rs} rule r{n:05d}"
            c = Cond()
            for side, f in (("source", "src"), ("destination", "dst")):
                if f"{side} address" in r:
                    setattr(c, f, H.inter(getattr(c, f), H.ipset([r[f"{side} address"]])))
                for g in ("address-group", "network-group"):
                    if f"{side} group {g}" in r:
                        setattr(c, f, H.inter(getattr(c, f), H.ipset(m.groups[g][r[f"{side} group {g}"]])))
            if "protocol" in r:
                e.L.append(f"{b} match protocol {r['protocol']}")
            # Batfish v2026.08.27 keeps only the LAST 'match source-address'/'destination-address'
            # line of a NAT rule (NatRuleMatchToHeaderSpace overwrites). Use one global
            # address-book address-set per side, which resolves to the union.
            for f, kw in (("src", "source-address-name"), ("dst", "destination-address-name")):
                v = getattr(c, f)
                if v is None:
                    continue
                if len(v) == 0:
                    gw.unsup_regions[f"NAT:{i}"].append((c, f"nat rule {n}: empty group (never matches)", f"nat:{n}"))
                    v = H.ipset(["255.255.255.255/32"])
                e.L.append(f"{b} match {kw} {addrset(e, v)}")
            if r.get("exclude"):
                e.L.append(f"{b} then source-nat off")
            elif r.get("translation address") == "masquerade":
                if len(m.ifaces[i]["addr"]) != 1:
                    gw.unsup_regions[f"NAT:{i}"].append((c, f"masquerade on multi-address {i}", f"nat:{n}"))
                e.L.append(f"{b} then source-nat interface")
            else:
                ta = r["translation address"]
                pn = "pool_" + ta.replace(".", "_").replace("/", "_")
                if pn not in pools:
                    pools.add(pn)
                    e.L.append(f"set security nat source pool {pn} address {ta if '/' in ta else ta + '/32'}")
                    e.L.append(f"set security nat source pool {pn} port no-translation")
                e.L.append(f"{b} then source-nat pool {pn}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src"); ap.add_argument("dst"); ap.add_argument("--cls", choices=["new", "est", "nat"], required=True)
    ap.add_argument("--sidecar")
    a = ap.parse_args()
    gw = Gateway(open(a.src).read(), a.cls)
    e, nterms, ifmap = emit(gw, a.cls)
    open(a.dst, "w").write("#RANCID-CONTENT-TYPE: juniper\n" + "\n".join(e.L) + "\n")
    cls_counts = Counter(v[0] for v in gw.m.cls.values())
    side = {"host": gw.m.host, "cls": a.cls, "ifmap": ifmap, "zone_of": gw.zone_of, "local_zone": gw.local_zone,
            "global_unsupported": gw.global_unsup, "path_classes": dict(cls_counts),
            "out_of_scope": dict(Counter(v[1] for v in gw.m.cls.values() if v[0] == "OUT_OF_SCOPE")),
            "unsup_regions": {k: [(repr(c), why) for c, why, _ in v] for k, v in gw.unsup_regions.items()},
            "stats": dict(gw.stats), "tcp_loose": gw.m.tcp_loose(),
            "loose_independent_first_packet": "no rule matches ct state new/invalid (else UNSUPPORTED), so a first packet's verdict is the same for loose=0 (INVALID) and loose=1 (NEW); loose changes only SNAT of bare non-SYN TCP and whether later packets become ESTABLISHED",
            "terms": e.terms, "n_terms": nterms, "n_lines": len(e.L),
            "local_ips": H.cidrs(gw.local), "regions": {k: H.cidrs(v)[:50] for k, v in gw.regions.items()}}
    if a.sidecar:
        json.dump(side, open(a.sidecar, "w"), indent=1, default=str)
    print(gw.m.host, a.cls, "lines", len(e.L), "terms", nterms, "global_unsup", len(gw.global_unsup),
          "unsup_regions", sum(len(v) for v in gw.unsup_regions.values()), dict(gw.stats))


if __name__ == "__main__":
    main()
