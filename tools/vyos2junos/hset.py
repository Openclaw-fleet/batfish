"""Exact header-space algebra for the translator: IPv4 sets as disjoint integer intervals,
port sets as intervals, protocol sets, and a TCP-flag constraint.

A Cond is a conjunction over dimensions; None in a dimension means "unconstrained".
"""
import ipaddress

FULL_IP = ((0, 2**32 - 1),)
FULL_PORT = ((0, 65535),)


def norm(iv):
    iv = sorted(iv)
    out = []
    for a, b in iv:
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return tuple(out)


def ipset(values):
    """values: iterable of 'a.b.c.d', 'a.b.c.d/n', 'a-b' or ip_network objects."""
    iv = []
    for v in values:
        if isinstance(v, (ipaddress.IPv4Network,)):
            iv.append((int(v.network_address), int(v.broadcast_address)))
            continue
        v = str(v)
        if "-" in v:
            a, b = v.split("-")
            iv.append((int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))))
        else:
            n = ipaddress.IPv4Network(v, strict=False)
            iv.append((int(n.network_address), int(n.broadcast_address)))
    return norm(iv)


def portset(spec):
    iv = []
    for p in str(spec).split(","):
        if "-" in p:
            a, b = p.split("-"); iv.append((int(a), int(b)))
        else:
            iv.append((int(p), int(p)))
    return norm(iv)


def inter(a, b):
    if a is None:
        return b
    if b is None:
        return a
    out, i, j = [], 0, 0
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return tuple(out)


def union(a, b):
    if a is None or b is None:
        return None
    return norm(list(a) + list(b))


def minus(a, b, full=FULL_IP):
    if a is None:
        a = full
    if b is None:
        return ()
    out = []
    for lo, hi in a:
        cur = lo
        for blo, bhi in b:
            if bhi < cur or blo > hi:
                continue
            if blo > cur:
                out.append((cur, blo - 1))
            cur = max(cur, bhi + 1)
            if cur > hi:
                break
        if cur <= hi:
            out.append((cur, hi))
    return tuple(out)


def contains(a, x):
    return a is None or any(lo <= x <= hi for lo, hi in a)


def cidrs(iv):
    out = []
    for a, b in iv:
        out += [str(n) for n in ipaddress.summarize_address_range(ipaddress.IPv4Address(a), ipaddress.IPv4Address(b))]
    return out


def size(iv):
    return sum(b - a + 1 for a, b in iv)


DIMS = ("src", "dst", "proto", "dport", "sport", "flags")


class Cond:
    """flags: None | 'SYNONLY' (tcp syn=1 ack=0) | 'ACKNOSYN' (tcp syn=0 ack=1)."""
    __slots__ = DIMS

    def __init__(self, src=None, dst=None, proto=None, dport=None, sport=None, flags=None):
        self.src, self.dst, self.proto, self.dport, self.sport, self.flags = src, dst, proto, dport, sport, flags

    def __and__(self, o):
        if self.flags and o.flags and self.flags != o.flags:
            return None
        proto = self.proto if o.proto is None else (o.proto if self.proto is None else self.proto & o.proto)
        flags = self.flags or o.flags
        if flags:
            proto = frozenset({"tcp"}) if proto is None else proto & {"tcp"}
        dport = inter(self.dport, o.dport)
        sport = inter(self.sport, o.sport)
        if dport is not None or sport is not None:
            proto = frozenset({"tcp", "udp"}) if proto is None else proto & {"tcp", "udp"}
        c = Cond(inter(self.src, o.src), inter(self.dst, o.dst), proto, dport, sport, flags)
        return None if c.empty() else c

    def empty(self):
        return any(v is not None and len(v) == 0 for v in (self.src, self.dst, self.proto, self.dport, self.sport))

    def matches(self, pkt):
        """pkt: dict src,dst (int), proto (str), sport,dport (int), syn, ack (bool)."""
        if not contains(self.src, pkt["src"]) or not contains(self.dst, pkt["dst"]):
            return False
        if self.proto is not None and pkt["proto"] not in self.proto:
            return False
        if self.dport is not None and (pkt["proto"] not in ("tcp", "udp") or not contains(self.dport, pkt["dport"])):
            return False
        if self.sport is not None and (pkt["proto"] not in ("tcp", "udp") or not contains(self.sport, pkt["sport"])):
            return False
        if self.flags == "SYNONLY" and not (pkt["proto"] == "tcp" and pkt["syn"] and not pkt["ack"]):
            return False
        if self.flags == "ACKNOSYN" and not (pkt["proto"] == "tcp" and pkt["ack"] and not pkt["syn"]):
            return False
        return True

    def key(self):
        return tuple(getattr(self, d) if d != "proto" else (tuple(sorted(self.proto)) if self.proto else None) for d in DIMS)

    def overlaps(self, o):
        return (self & o) is not None

    def __repr__(self):
        parts = []
        for d in DIMS:
            v = getattr(self, d)
            if v is None:
                continue
            if d in ("src", "dst"):
                c = cidrs(v); v = ",".join(c[:4]) + (f"…(+{len(c)-4})" if len(c) > 4 else "")
            elif d in ("dport", "sport"):
                v = ",".join(f"{a}" if a == b else f"{a}-{b}" for a, b in v)
            elif d == "proto":
                v = ",".join(sorted(v))
            parts.append(f"{d}={v}")
        return "Cond(" + " ".join(parts) + ")"


ANY = Cond()
