"""Independent per-packet reference evaluator of VyOS (vyos-1x rev dbde15e2) netfilter semantics
for a rendered gateway. Shares only the config parser (vyosmodel) with the translator: no Cond
algebra, no region partition, no inlining. Emulates base chains in hook/priority order, nft
jump/return verdict stack, kernel routing (LPM over connected+static), K1 martian/local-source
drop, and SNAT rule selection.

verdict(pkt) -> ('accept'|'deny'|'noroute'|'unsupported', detail, snat_src or None)
pkt: iif ('ethN' or 'local' for router-originated), src, dst (str), proto, sport, dport,
     syn, ack (bool), ct ('new'|'invalid'|'established').
"""
import ipaddress
from vyosmodel import Model, load_commands, nets, ports

MARTIAN = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4")]


class Ref:
    def __init__(self, text, tcp_loose="both"):
        """tcp_loose: explicit model input for nf_conntrack_tcp_loose: 0, 1, or "both" (default:
        evaluate a bare non-SYN first packet under both and report a result only when they agree;
        a loose-dependent verdict is UNSUPPORTED, a loose-dependent SNAT is reported as such).
        "config" uses the value the render implies (sysctl/CLI/cron) - only when lane-2 VM evidence
        confirms it."""
        self.m = Model(load_commands(text))
        self.loose = self.m.tcp_loose()["steady_state"] if tcp_loose == "config" else tcp_loose
        m = self.m
        self.zone_of = {i: z for z, c in m.zones.items() if not c["local"] for i in c["members"]}
        self.lz = next((z for z, c in m.zones.items() if c["local"]), None)
        self.local = {ipaddress.ip_interface(a).ip for e, i in m.ifaces.items() if not i["disable"] for a in i["addr"]}
        self.bcast = set()
        for e, i in m.ifaces.items():
            if i["disable"]:
                continue
            for a in i["addr"]:
                n = ipaddress.ip_interface(a).network
                if n.prefixlen < 31:
                    self.bcast |= {n.network_address, n.broadcast_address}

    # --- rule matching, read directly from the rule dict ---
    def _ipin(self, ip, r, side):
        if f"{side} address" in r and ip not in nets([r[f"{side} address"]])[0]:
            if not any(ip in n for n in nets([r[f"{side} address"]])):
                return False
        for g in ("address-group", "network-group"):
            k = f"{side} group {g}"
            if k in r and not any(ip in n for n in nets(self.m.groups[g][r[k]])):
                return False
        return True

    def match(self, r, p):
        """True/False, or raises ValueError('unsupported ...')."""
        if r.get("disable"):
            return False
        if r.get("unsupported"):
            raise ValueError("unsupported rule field " + ",".join(r["unsupported"]))
        st = r.get("state")
        if st:
            if p["ct"] == "established":
                if "established" not in st:
                    return False
            else:
                return False  # new / invalid never match established|related
        if "protocol" in r and r["protocol"] != p["proto"]:
            return False
        if not self._ipin(p["src"], r, "source") or not self._ipin(p["dst"], r, "destination"):
            return False
        for side, f in (("destination", "dport"), ("source", "sport")):
            if f"{side} port" in r and (p["proto"] not in ("tcp", "udp") or p[f] not in ports(r[f"{side} port"])):
                return False
        if r.get("tcpflags"):  # rendered only as {syn, not ack}: (flags & (syn|ack)) == syn
            if p["proto"] != "tcp" or not (p["syn"] and not p["ack"]):
                return False
        if r.get("limit") or "source mac-address" in r:
            raise ValueError("depends on rate/MAC")
        return True

    def run_chain(self, name, p, depth=0):
        ch = self.m.chains[name]
        for num in sorted(ch["rules"]):
            r = ch["rules"][num]
            try:
                hit = self.match(r, p)
            except ValueError as e:
                # evaluate both branches; if they agree the rule is verdict-neutral for this packet
                if "rate/MAC" in str(e):
                    a = r.get("action")
                    rest = self._rest(name, num, p, depth)
                    va = "deny" if a in ("drop", "reject") else a
                    vr = "deny" if rest in ("drop", "reject") else rest
                    if va == vr:
                        return a
                    raise ValueError(f"{name}:{num} verdict depends on rate/MAC")
                raise ValueError(f"{name}:{num} {e}")
            if not hit:
                continue
            a = r.get("action")
            if a == "jump":
                v = self.run_chain(r["jump-target"], p, depth + 1)
                if v == "return":
                    continue
                return v
            return a
        d = ch["default"] or ("accept" if name == "__FWD__" else "drop")
        return d

    def _rest(self, name, after, p, depth):
        ch = self.m.chains[name]
        for num in sorted(ch["rules"]):
            if num <= after:
                continue
            r = ch["rules"][num]
            if not self.match(r, p):
                continue
            a = r.get("action")
            if a == "jump":
                v = self.run_chain(r["jump-target"], p, depth + 1)
                if v == "return":
                    continue
                return v
            return a
        return ch["default"] or "drop"

    def route(self, dst):
        best = None
        for n, e, nh in self.m.rib():
            if dst in n and (best is None or n.prefixlen > best[0].prefixlen):
                best = (n, e, nh)
        return best

    def snat(self, p, oif):
        for n, r in sorted(self.m.nat.items()):
            if r.get("disable"):
                continue
            if r.get("oif", oif) != oif:
                continue
            ok = True
            for side, ip in (("source", p["src"]), ("destination", p["dst"])):
                if f"{side} address" in r and not any(ip in x for x in nets([r[f"{side} address"]])):
                    ok = False
                for g in ("address-group", "network-group"):
                    k = f"{side} group {g}"
                    if k in r and not any(ip in x for x in nets(self.m.groups[g][r[k]])):
                        ok = False
            if "protocol" in r and r["protocol"] != p["proto"]:
                ok = False
            if not ok:
                continue
            if r.get("exclude"):
                return None, f"nat:{n}:exclude"
            ta = r["translation address"]
            if ta == "masquerade":
                addrs = self.m.ifaces[oif]["addr"]
                if len(addrs) != 1:
                    return "unsupported", f"nat:{n}:masquerade-multiaddr"
                return str(ipaddress.ip_interface(addrs[0]).ip), f"nat:{n}:masquerade"
            return ta.split("/")[0], f"nat:{n}"
        return None, "nat:none"

    def verdict(self, p):
        bare = p.get("ct") == "auto" and p.get("proto") == "tcp" and not (p.get("syn") and not p.get("ack"))
        if bare and self.loose == "both":
            r0 = self._verdict1(dict(p, ct="invalid")); r1 = self._verdict1(dict(p, ct="new"))
            if r0[0] != r1[0]:
                return ("unsupported", f"tcp_loose-dependent verdict (loose=0:{r0[0]} loose=1:{r1[0]})", None)
            if r0[2] != r1[2]:
                return (r0[0], r0[1] + " [loose-independent verdict]", f"loose-dependent(0:{r0[2]},1:{r1[2]})")
            return (r0[0], r0[1] + " [loose-independent]", r0[2])
        if bare:
            p = dict(p, ct="new" if self.loose else "invalid")
        elif p.get("ct") == "auto":
            p = dict(p, ct="new")
        return self._verdict1(p)

    def _verdict1(self, p):
        p = dict(p)
        p["src"] = ipaddress.ip_address(p["src"]); p["dst"] = ipaddress.ip_address(p["dst"])
        try:
            return self._verdict(p)
        except ValueError as e:
            return ("unsupported", str(e), None)

    def _verdict(self, p):
        if p["ct"] == "related":
            return ("unsupported", "related flow class", None)
        if p["dst"] in self.bcast or p["dst"] == ipaddress.ip_address("255.255.255.255") or \
                any(p["dst"] in n for n in MARTIAN):
            return ("unsupported", "special destination", None)
        if p["iif"] == "local":
            return self._local_out(p)
        if p["src"] in self.local or any(p["src"] in n for n in MARTIAN):
            return ("deny", "kernel K1 martian/local source", None)
        zi = self.zone_of.get(p["iif"])
        if p["dst"] in self.local:  # input hook
            if self.lz is None:
                return ("accept", "no local zone", None)
            ch = self.m.zones[self.lz]["from"].get(zi) if zi else None
            v = self.run_chain(ch, p) if ch else self.m.zones[self.lz]["default"]
            return ("accept" if v in ("accept", "return") else "deny", f"input:{ch or 'default'}", None)
        rt = self.route(p["dst"])
        if rt is None:
            return ("noroute", "no route", None)
        n, oif, nh = rt
        if oif is None:
            return ("deny", "blackhole", None)
        if "__FWD__" in self.m.chains:  # priority 0 base chain
            v = self.run_chain("__FWD__", p)
            if v in ("drop", "reject"):
                return ("deny", "forward-filter", None)
        zo = self.zone_of.get(oif)
        if zo is not None:  # priority 1 base chain VYOS_ZONE_FORWARD
            if zi != zo:
                ch = self.m.zones[zo]["from"].get(zi) if zi else None
                v = self.run_chain(ch, p) if ch else self.m.zones[zo]["default"]
                if v not in ("accept", "return"):
                    return ("deny", f"zone:{ch or zo + ':default'}", None)
        s = None
        if p["ct"] == "new":
            s, why = self.snat(p, oif)
        return ("accept", f"oif={oif}", s)

    def _local_out(self, p):
        rt = self.route(p["dst"])
        if rt is None or rt[1] is None:
            return ("noroute", "no route", None)
        oif = rt[1]
        zo = self.zone_of.get(oif)
        if self.lz is None:
            return ("accept", "no local zone", None)
        ch = self.m.zones[zo]["from"].get(self.lz) if zo else None
        v = self.run_chain(ch, p) if ch else self.m.zones[self.lz]["default"]
        return ("accept" if v in ("accept", "return") else "deny", f"output:{ch or 'default'} oif={oif}", None)
