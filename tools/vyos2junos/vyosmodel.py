"""VyOS config model for the ProxMoxSDN Batfish spike (analysis only).

* load_commands(): applies a rendered vyos-commands.sh sequentially (set + delete), like a
  configure session would, and returns the final set of config paths.
* load_boot(): flattens a config.boot (curly syntax) into the same path tuples, used as an
  independent parity check of the set/delete semantics.
* Model: typed view of the paths the translator and the reference evaluator consume. Every path
  is classified as MODELED, OUT_OF_SCOPE (with a stated reason) or UNSUPPORTED. Nothing is
  dropped silently.
"""
import ipaddress, re, shlex
from collections import defaultdict, OrderedDict

SINGLE_LEAF = {"action", "default-action", "protocol", "description", "jump-target", "port", "rate", "burst",
               "mac-address", "host-name", "address-group", "network-group"}


def _single(path):
    if len(path) < 2:
        return False
    k = path[-2]
    if k in SINGLE_LEAF:
        return True
    if k == "address" and len(path) >= 3 and path[-3] in ("source", "destination", "translation"):
        return True
    if k == "name" and len(path) >= 3 and path[-3] == "outbound-interface":
        return True
    return False


def load_commands(text):
    """Sequential set/delete application with a prefix index (O(total path tokens))."""
    paths = {}            # path -> insertion order
    idx = defaultdict(set)  # prefix -> set of full paths under it

    def add(p):
        paths[p] = len(paths)
        for i in range(1, len(p) + 1):
            idx[p[:i]].add(p)

    def remove(p):
        paths.pop(p, None)
        for i in range(1, len(p) + 1):
            idx[p[:i]].discard(p)

    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        toks = shlex.split(raw)
        op, path = toks[0], tuple(toks[1:])
        if op == "set":
            if _single(path):
                for p in [p for p in idx.get(path[:-1], ()) if len(p) == len(path)]:
                    remove(p)
            add(path)
        elif op == "delete":
            for p in list(idx.get(path, ())):
                remove(p)
        else:
            raise ValueError("unknown op: " + raw)
    return set(paths)


def load_boot(text):
    out, stack, children = set(), [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("/*") or line.startswith("//"):
            continue
        if line == "}":
            if not children.pop():  # empty block `next-hop X { }` is a leaf
                out.add(tuple(t for s in stack for t in s))
            stack.pop()
            continue
        if children:
            children[-1] = True
        toks = shlex.split(line.rstrip("{").strip()) if line.endswith("{") else shlex.split(line)
        if line.endswith("{"):
            stack.append(tuple(toks)); children.append(False)
        else:
            out.add(tuple(t for s in stack for t in s) + tuple(toks))
    return out


def nets(values):
    out = []
    for v in values:
        if "-" in v:
            a, b = v.split("-")
            out += list(ipaddress.summarize_address_range(ipaddress.ip_address(a), ipaddress.ip_address(b)))
        else:
            out.append(ipaddress.ip_network(v, strict=False))
    return out


def ports(spec):
    s = set()
    for p in str(spec).split(","):
        if "-" in p:
            a, b = p.split("-"); s |= set(range(int(a), int(b) + 1))
        else:
            s.add(int(p))
    return frozenset(s)


# Paths that do not influence the L3 forward/local verdict model, with the reason. Matching is by
# prefix; anything not listed here and not consumed by Model is UNSUPPORTED.
OUT_OF_SCOPE = [
    (("system",), "router management (hostname taken; services/login/syslog/ntp/conntrack timeouts don't change filter verdicts)"),
    (("service",), "router services: whether a local-in-accepted port has a listener is not modelled"),
    (("interfaces", "ethernet", "*", "hw-id"), "L2 identity"),
    (("interfaces", "ethernet", "*", "mac"), "L2 identity"),
    (("interfaces", "ethernet", "*", "description"), "documentation"),
    (("interfaces", "ethernet", "*", "offload"), "NIC offload"),
    (("interfaces", "ethernet", "*", "ipv6"), "IPv6 not modelled (no IPv6 addresses rendered; no-default-link-local only)"),
    (("interfaces", "ethernet", "*", "ip", "adjust-mss"), "TCP MSS clamp: no verdict effect"),
    (("interfaces", "ethernet", "*", "ip", "enable-proxy-arp"), "L2/ARP: affects which hosts send to the gateway, not the verdict"),
    (("protocols", "static", "arp"), "static neighbour pinning: L2, not the verdict"),
    (("firewall", "group", "*", "*", "description"), "documentation"),
    (("firewall", "ipv4", "name", "*", "description"), "documentation"),
    (("firewall", "ipv4", "forward", "filter", "description"), "documentation"),
    (("firewall", "zone", "*", "description"), "documentation"),
]


def _match(prefix, path):
    return len(path) >= len(prefix) and all(a == "*" or a == b for a, b in zip(prefix, path))


class Model:
    """Typed view. Records each path's classification in self.cls[path]."""

    RULE_FIELDS = ("action", "description", "jump-target", "protocol", "log", "disable", "state", "tcp", "limit",
                   "source", "destination")

    def __init__(self, paths):
        self.paths = paths
        self.cls = {}
        self.unsupported = []      # (path, reason)  -> global: whole-gateway result is UNSUPPORTED
        self.host = None
        self.ifaces = OrderedDict()
        self.routes = []           # (prefix, kind, arg)
        self.groups = {"address-group": defaultdict(list), "network-group": defaultdict(list)}
        self.zones = OrderedDict()
        self.chains = defaultdict(lambda: {"default": None, "rules": defaultdict(dict)})
        self.nat = defaultdict(dict)
        for p in sorted(paths):
            self._consume(p)
        self._post()

    def _mark(self, p, c, reason=None):
        self.cls[p] = (c, reason)
        if c == "UNSUPPORTED":
            self.unsupported.append((" ".join(p), reason))

    def _consume(self, p):
        if p[:2] == ("system", "host-name"):
            self.host = p[2]; return self._mark(p, "MODELED")
        if p[:2] == ("interfaces", "ethernet"):
            i = self.ifaces.setdefault(p[2], {"addr": [], "disable": False})
            if len(p) == 5 and p[3] == "address":
                if p[4] == "dhcp":
                    return self._mark(p, "UNSUPPORTED", "dhcp address")
                i["addr"].append(p[4]); return self._mark(p, "MODELED")
            if len(p) == 4 and p[3] == "disable":
                i["disable"] = True; return self._mark(p, "MODELED")
        if p[:3] == ("protocols", "static", "route") and len(p) >= 5:
            if len(p) == 6 and p[4] in ("next-hop", "interface"):
                self.routes.append((p[3], p[4], p[5])); return self._mark(p, "MODELED")
            if len(p) == 5 and p[4] == "blackhole":
                self.routes.append((p[3], "blackhole", None)); return self._mark(p, "MODELED")
            return self._mark(p, "UNSUPPORTED", "static route option")
        if p[:2] == ("firewall", "group"):
            if p[2] in self.groups and len(p) == 6 and p[4] == ("address" if p[2] == "address-group" else "network"):
                self.groups[p[2]][p[3]].append(p[5]); return self._mark(p, "MODELED")
        if p[:2] == ("firewall", "zone") and len(p) >= 4:
            z = self.zones.setdefault(p[2], {"members": [], "default": None, "local": False, "from": {}})
            if p[3] == "member" and len(p) == 6 and p[4] == "interface":
                z["members"].append(p[5]); return self._mark(p, "MODELED")
            if p[3] == "default-action" and len(p) == 5:
                z["default"] = p[4]; return self._mark(p, "MODELED")
            if p[3] == "local-zone" and len(p) == 4:
                z["local"] = True; return self._mark(p, "MODELED")
            if p[3] == "from" and len(p) == 8 and p[5:7] == ("firewall", "name"):
                z["from"][p[4]] = p[7]; return self._mark(p, "MODELED")
        if p[:3] == ("firewall", "ipv4", "name") or p[:4] == ("firewall", "ipv4", "forward", "filter"):
            if p[2] == "name":
                name, rest = p[3], p[4:]
            else:
                name, rest = "__FWD__", p[4:]
            ch = self.chains[name]
            if len(rest) == 2 and rest[0] == "default-action":
                ch["default"] = rest[1]; return self._mark(p, "MODELED")
            if rest and rest[0] == "rule" and len(rest) >= 3:
                r = ch["rules"][int(rest[1])]
                f = rest[2:]
                k = None
                if f[0] in ("log", "disable") and len(f) == 1:
                    r[f[0]] = True; k = "MODELED"
                elif f[0] in ("action", "jump-target", "protocol", "description") and len(f) == 2:
                    r[f[0]] = f[1]; k = "MODELED"
                elif f[0] == "state" and len(f) == 2:
                    r.setdefault("state", set()).add(f[1]); k = "MODELED"
                elif f[:2] == ("tcp", "flags"):
                    r.setdefault("tcpflags", set()).add(" ".join(f[2:])); k = "MODELED"
                elif f[0] == "limit" and len(f) == 3 and f[1] in ("rate", "burst"):
                    r.setdefault("limit", {})[f[1]] = f[2]; k = "MODELED"
                elif f[0] in ("source", "destination") and len(f) == 3 and f[1] in ("address", "port", "mac-address"):
                    if f[2].startswith("!"):
                        r.setdefault("unsupported", []).append("negated " + " ".join(f[:2]))
                        k = "UNSUPPORTED_SCOPED"
                    else:
                        r[f"{f[0]} {f[1]}"] = f[2]; k = "MODELED"
                elif f[0] in ("source", "destination") and len(f) == 4 and f[1] == "group" and f[2] in ("address-group", "network-group"):
                    r[f"{f[0]} group {f[2]}"] = f[3]; k = "MODELED"
                if k is None:
                    r.setdefault("unsupported", []).append(" ".join(f[:-1] if len(f) > 1 else f))
                    k = "UNSUPPORTED_SCOPED"
                return self._mark(p, k, None if k == "MODELED" else "rule field; verdicts touching this rule are UNSUPPORTED")
        if p[:3] == ("nat", "source", "rule") and len(p) >= 5:
            r = self.nat[int(p[3])]
            f = p[4:]
            if f == ("exclude",) or f == ("disable",):
                r[f[0]] = True; return self._mark(p, "MODELED")
            if len(f) == 2 and f[0] in ("description", "protocol"):
                r[f[0]] = f[1]; return self._mark(p, "MODELED")
            if len(f) == 3 and f[0] in ("source", "destination", "translation") and f[1] in ("address", "port"):
                if f[2].startswith("!") or (f[0] == "translation" and f[1] == "port"):
                    return self._mark(p, "UNSUPPORTED", "nat field " + " ".join(f[:2]))
                r[f"{f[0]} {f[1]}"] = f[2]; return self._mark(p, "MODELED")
            if len(f) == 4 and f[1] == "group" and f[0] in ("source", "destination") and f[2] in ("address-group", "network-group"):
                r[f"{f[0]} group {f[2]}"] = f[3]; return self._mark(p, "MODELED")
            if f[:2] == ("outbound-interface", "name") and len(f) == 3:
                r["oif"] = f[2]; return self._mark(p, "MODELED")
            return self._mark(p, "UNSUPPORTED", "nat field")
        for pre, why in OUT_OF_SCOPE:
            if _match(pre, p):
                return self._mark(p, "OUT_OF_SCOPE", why)
        return self._mark(p, "UNSUPPORTED", "construct not modelled: " + " ".join(p[:3]))

    def _post(self):
        for name, ch in self.chains.items():
            if ch["default"] is None:
                self.unsupported.append((f"firewall chain {name}", "no default-action (refusing to assume)"))
            for n, r in ch["rules"].items():
                for k, v in list(r.items()):
                    if k.endswith(("group address-group", "group network-group")):
                        kind = k.split()[-1]
                        if v not in self.groups[kind]:
                            self.unsupported.append((f"{name} rule {n}", f"references undefined {kind} {v}"))
                if r.get("action") == "jump" and r.get("jump-target") not in self.chains:
                    self.unsupported.append((f"{name} rule {n}", "jump to undefined chain"))
                if r.get("action") not in ("accept", "drop", "reject", "jump", "return"):
                    r.setdefault("unsupported", []).append(f"action {r.get('action')}")
                if r.get("tcpflags") and r["tcpflags"] != {"syn", "not ack"}:
                    r.setdefault("unsupported", []).append("tcp flags " + ",".join(sorted(r["tcpflags"])))
                if r.get("state") and not r["state"] <= {"established", "related"}:
                    r.setdefault("unsupported", []).append("state " + ",".join(sorted(r["state"])))
                if r.get("limit") and set(r["limit"]) - {"rate", "burst"}:
                    r.setdefault("unsupported", []).append("limit option")
        for z, c in self.zones.items():
            if c["default"] is None:
                self.unsupported.append((f"zone {z}", "no default-action"))
            for fz, ch in c["from"].items():
                if fz not in self.zones:
                    self.unsupported.append((f"zone {z} from {fz}", "unknown from-zone"))
                if ch not in self.chains:
                    self.unsupported.append((f"zone {z} from {fz}", "undefined chain " + ch))
        seen = defaultdict(set)
        for pfx, kind, arg in self.routes:
            seen[pfx].add((kind, arg))
        for pfx, s in seen.items():
            if len(s) > 1:
                self.unsupported.append((f"static route {pfx}", "multiple next-hops (ECMP) not modelled"))
        for n, r in self.nat.items():
            ta = r.get("translation address")
            if not r.get("exclude") and ta is None:
                self.unsupported.append((f"nat source rule {n}", "no translation"))
            if ta and ta != "masquerade" and ("-" in ta or "/" in ta and not ta.endswith("/32")):
                self.unsupported.append((f"nat source rule {n}", "translation range/prefix"))
            for k, v in r.items():
                if k.endswith(("group address-group", "group network-group")) and v not in self.groups[k.split()[-1]]:
                    self.unsupported.append((f"nat source rule {n}", f"undefined group {v}"))

    def group(self, kind, name):
        return nets(self.groups[kind][name])

    def tcp_loose(self):
        """Steady-state nf_conntrack_tcp_loose implied by the config, plus whether a transient
        loose=1 window exists (VyOS system_conntrack.py rewrites the sysctl from
        `system conntrack tcp loose`, default enable, on any conntrack commit)."""
        cli_disable = ("system", "conntrack", "tcp", "loose", "disable") in self.paths
        sysctl0 = ("system", "sysctl", "parameter", "net.netfilter.nf_conntrack_tcp_loose", "value", "0") in self.paths
        cron0 = any(p[:4] == ("system", "task-scheduler", "task", "strict-conntrack") and
                    "nf_conntrack_tcp_loose=0" in " ".join(p) for p in self.paths)
        steady = 0 if (cli_disable or sysctl0 or cron0) else 1
        return {"steady_state": steady, "cli_disable": cli_disable, "sysctl_param_0": sysctl0, "cron_reassert_0": cron0,
                "transient_loose1_window": bool(steady == 0 and not cli_disable)}

    # ---- routing (static + connected; exact LPM, connected beats static on equal prefix) ----
    def connected(self):
        out = []
        for e, i in self.ifaces.items():
            if i["disable"]:
                continue
            for a in i["addr"]:
                out.append((ipaddress.ip_interface(a).network, e))
        return out

    def local_ips(self):
        return sorted({ipaddress.ip_interface(a).ip for i in self.ifaces.values() if not i["disable"] for a in i["addr"]})

    def bcast_ips(self):
        """Network and broadcast addresses of connected subnets (Linux: local broadcast routes)."""
        s = set()
        for n, _ in self.connected():
            if n.prefixlen < 31:
                s.add(n.network_address); s.add(n.broadcast_address)
        return sorted(s)

    def rib(self):
        """List of (prefix, egress_iface or None for blackhole, nexthop ip or None)."""
        conn = self.connected()
        out = [(n, e, None) for n, e in conn]
        cset = {n for n, _ in conn}
        for p, kind, arg in self.routes:
            n = ipaddress.ip_network(p)
            if n in cset:
                continue  # connected wins
            if kind == "interface":
                out.append((n, arg, None))
            elif kind == "blackhole":
                out.append((n, None, None))
            else:
                nh = ipaddress.ip_address(arg)
                best = None
                for cn, e in conn:
                    if nh in cn and (best is None or cn.prefixlen > best[0].prefixlen):
                        best = (cn, e)
                if best:
                    out.append((n, best[1], nh))
                # unresolvable next-hop: route inactive (kernel refuses it); same in Batfish
        return out

    def lookup(self, dst):
        best = None
        for n, e, nh in self.rib():
            if dst in n and (best is None or n.prefixlen > best[0].prefixlen):
                best = (n, e, nh)
        return best
