"""Flow corpus generation (targeted boundary points + random) for the translator validation, and
the Batfish-side evaluator shared with lane-2 corpus checks."""
import ipaddress, json, random
from vyosmodel import load_commands, Model, nets, ports
from pybatfish.datamodel.flow import HeaderConstraints

PERMIT = {"ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK", "NEIGHBOR_UNREACHABLE", "INSUFFICIENT_INFO"}
DENY = {"DENIED_IN", "DENIED_OUT", "NULL_ROUTED"}


def _pick(netlist, rnd):
    n = rnd.choice(netlist)
    if n.num_addresses <= 2:
        return n.network_address
    return n.network_address + rnd.randint(1, min(n.num_addresses - 2, 250))


def gen(text, n_target, n_random, seed=7):
    rnd = random.Random(seed)
    m = Model(load_commands(text))
    zone_of = {i: z for z, c in m.zones.items() if not c["local"] for i in c["members"]}
    lz = next((z for z, c in m.zones.items() if c["local"]), None)
    ifaces = [e for e, i in m.ifaces.items() if not i["disable"] and i["addr"]]
    subnet = {e: [ipaddress.ip_interface(a).network for a in m.ifaces[e]["addr"]] for e in ifaces}
    local = [ipaddress.ip_interface(a).ip for e in ifaces for a in m.ifaces[e]["addr"]]
    internet = [ipaddress.ip_network(x) for x in ("1.0.0.0/8", "8.8.0.0/16", "100.64.0.0/10", "192.0.2.0/24", "10.10.0.0/18")]
    flows = []

    def add(iif, src, dst, proto, dport, ct, syn, ack, why):
        flows.append({"iif": iif, "src": str(src), "dst": str(dst), "proto": proto, "sport": 40000 if proto != "icmp" else 0,
                      "dport": dport if proto != "icmp" else 0, "ct": ct, "syn": syn, "ack": ack, "why": why})

    def variants(iif, src, dst, proto, dport, why):
        if proto == "tcp":
            add(iif, src, dst, "tcp", dport, "new", True, False, why)
            add(iif, src, dst, "tcp", dport, "invalid", False, True, why + "/nonsyn")
            add(iif, src, dst, "tcp", dport, "established", False, True, why + "/est")
        else:
            add(iif, src, dst, proto, dport, "new", False, False, why)
            add(iif, src, dst, proto, dport, "established", False, False, why + "/est")

    # targeted: every rule of every chain reachable from each ingress zone
    pairs = []
    for zo, c in m.zones.items():
        for zi, ch in c["from"].items():
            pairs.append((zi, zo, ch))
    rnd.shuffle(pairs)
    budget = n_target
    for zi, zo, ch in pairs:
        if budget <= 0:
            break
        src_if = [e for e in ifaces if zone_of.get(e) == zi] if zi != lz else ["local"]
        if not src_if:
            continue
        if zo == lz:
            dst_pool = [ipaddress.ip_network(f"{x}/32") for x in local]
        else:
            dst_if = [e for e in ifaces if zone_of.get(e) == zo]
            if not dst_if:
                continue
            dst_pool = [n for e in dst_if for n in subnet[e]]
        rules = list(m.chains[ch]["rules"].items())
        targets = []
        for num, r in rules:
            for jt in ([r] + ([rr for _, rr in m.chains[r["jump-target"]]["rules"].items()] if r.get("action") == "jump" else [])):
                targets.append((num, jt))
        for num, r in targets[:40]:
            if budget <= 0:
                break
            iif = rnd.choice(src_if)
            if iif == "local":
                src = None
            else:
                srcs = []
                if "source address" in r:
                    srcs = nets([r["source address"]])
                for g in ("address-group", "network-group"):
                    if f"source group {g}" in r and m.groups[g].get(r[f"source group {g}"]):
                        srcs = nets(m.groups[g][r[f"source group {g}"]])
                src = _pick(srcs or subnet[iif], rnd)
            dsts = []
            if "destination address" in r:
                dsts = nets([r["destination address"]])
            for g in ("address-group", "network-group"):
                if f"destination group {g}" in r and m.groups[g].get(r[f"destination group {g}"]):
                    dsts = nets(m.groups[g][r[f"destination group {g}"]])
            dst = _pick(dsts or dst_pool, rnd)
            proto = r.get("protocol") or rnd.choice(["tcp", "udp", "icmp"])
            dport = 443
            if "destination port" in r:
                ps = sorted(ports(r["destination port"]))
                dport = rnd.choice([ps[0], ps[-1], ps[0] - 1 if ps[0] > 1 else ps[0], ps[-1] + 1])
            if src is None:
                src = "AUTO"
            variants(iif, src, dst, proto, dport, f"rule {ch}:{num}")
            budget -= 1
    # random
    allnets = [n for e in ifaces for n in subnet[e]] + internet
    for _ in range(n_random):
        iif = rnd.choice(ifaces + ["local"])
        src = "AUTO" if iif == "local" else _pick(subnet[iif] + (internet if zone_of.get(iif) == "wan" else []), rnd)
        dst = rnd.choice([_pick(allnets, rnd), rnd.choice(local)]) if rnd.random() < 0.85 else rnd.choice(local)
        proto = rnd.choice(["tcp", "udp", "icmp"])
        dport = rnd.choice([22, 53, 123, 443, 1514, 1515, 3025, 8080, 5432, 9100, 43000, 1, 65535])
        variants(iif, src, dst, proto, dport, "random")
    return m, flows


def resolve_auto_src(m, flow, ref):
    """Router-originated flows: kernel source selection = primary address of the egress iface."""
    if flow["src"] != "AUTO":
        return flow
    rt = ref.route(ipaddress.ip_address(flow["dst"]))
    f = dict(flow)
    if rt is None or rt[1] is None or not m.ifaces[rt[1]]["addr"]:
        f["src"] = "0.0.0.0"
    else:
        f["src"] = str(ipaddress.ip_interface(m.ifaces[rt[1]]["addr"][0]).ip)
    return f


def bf_headers(f):
    h = dict(srcIps=f["src"], dstIps=f["dst"], ipProtocols=[f["proto"].upper()])
    if f["proto"] in ("tcp", "udp"):
        h.update(srcPorts=str(f["sport"]), dstPorts=str(f["dport"]))
    else:
        h.update(icmpTypes=[int(f.get("icmp_type", 8))], icmpCodes=[int(f.get("icmp_code", 0))])
    if f["proto"] == "tcp":
        h["tcpFlags"] = [{"tcpFlags": {"syn": bool(f["syn"]), "ack": bool(f["ack"]), "rst": False, "fin": False,
                                       "urg": False, "psh": False, "ece": False, "cwr": False},
                          "useSyn": True, "useAck": True, "useRst": True, "useFin": True}]
    return HeaderConstraints(**h)


def bf_eval(bf, host, ifmap, f):
    """Traceroute in the snapshot already selected for f's class. Returns (verdict, oif, disp)."""
    loc = host if f["iif"] == "local" else f"@enter({host}[{ifmap[f['iif']]}.0])"
    fr = bf.q.traceroute(startLocation=loc, headers=bf_headers(f)).answer().frame()
    traces = [t for tr in fr["Traces"] for t in tr]
    disp = sorted({str(t.disposition) for t in traces})
    oif = None
    for t in traces:
        for st in t.hops[-1].steps:
            o = getattr(st.detail, "outputInterface", None)
            if o:
                oif = o
    if set(disp) <= PERMIT and disp:
        v = "accept"
    elif set(disp) <= DENY and disp:
        v = "deny"
    elif disp == ["NO_ROUTE"]:
        v = "noroute"
    else:
        v = "other:" + ",".join(disp)
    return v, oif, disp, traces
