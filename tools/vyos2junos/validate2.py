"""Differential validation: Batfish (translated snapshots) vs independent reference evaluator.
usage: validate2.py <snap_prefix> <render_dir> <n_target> <n_random> <node,...>"""
import os, ipaddress, json, sys, time, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bfmeasure import session, measure, RESULTS, WORK
from vyos_ref2 import Ref
from corpus import gen, resolve_auto_src, bf_eval, bf_headers

pfx, rdir, nt, nr = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
nodes = sys.argv[5].split(",")
bf = session("v2")
log, report = [], {}
for nd in nodes:
    text = open(f"{rdir}/{nd}/vyos-commands.sh").read()
    ref = Ref(text)
    m, flows = gen(text, nt, nr)
    host = m.host
    side = json.load(open(f"{WORK}/v2/sidecar-{pfx}-new/{nd}.json"))
    ifmap = side["ifmap"]
    res = collections.Counter(); mism = []; unsup_check = collections.Counter(); natres = collections.Counter(); natmis = []
    t0 = time.time()
    by_cls = collections.defaultdict(list)
    for f in flows:
        f = resolve_auto_src(m, f, ref)
        by_cls["est" if f["ct"] == "established" else "new"].append(f)
    with measure(f"validate {host} flows={len(flows)}", log):
        for cls, fl in by_cls.items():
            bf.set_snapshot(f"{pfx}-{cls}")
            for f in fl:
                rv, why, snat = ref.verdict(f)
                if rv == "unsupported":
                    # fail-closed check: the flow must fall inside the UNSUP region of its ingress interface
                    key = ("UNSUP_OUT_" if f["iif"] == "local" else "UNSUP_") + (ifmap.get(f["iif"], "x").replace("/", "_").replace("-", "_"))
                    if f["iif"] == "local":
                        unsup_check["local-out unsupported (not fenced per-iface)"] += 1
                        continue
                    tf = bf.q.testFilters(nodes=host, filters=key, headers=bf_headers(f),
                                          startLocation=f"@enter({host}[{ifmap[f['iif']]}.0])").answer().frame()
                    act = str(tf["Action"].iloc[0]) if len(tf) else "NO_FILTER"
                    unsup_check["fenced" if act == "PERMIT" else "NOT_FENCED"] += 1
                    if act != "PERMIT":
                        mism.append({**f, "ref": rv, "why": why, "batfish": "not fenced"})
                    continue
                bv, oif, disp, traces = bf_eval(bf, host, ifmap, f)
                exp_oif = None
                if rv == "accept" and why.startswith("oif="):
                    exp_oif = ifmap[why[4:]] + ".0"
                ok = (bv == rv) and (exp_oif is None or oif == exp_oif)
                res[("agree" if ok else "DISAGREE", f["ct"], rv)] += 1
                if not ok:
                    mism.append({**f, "ref": rv, "why": why, "batfish": bv, "bf_oif": oif, "exp_oif": exp_oif, "disp": disp})
                if rv == "accept" and f["ct"] == "new" and exp_oif and f["iif"] != "local":
                    natres["checked"] += 1
                    bf.set_snapshot(f"{pfx}-nat")
                    fr = bf.q.traceroute(startLocation=f"@enter({host}[{ifmap[f['iif']]}.0])", headers=bf_headers(f)).answer().frame()
                    bsrc = None
                    for t in [t for tr in fr["Traces"] for t in tr]:
                        for h in t.hops:
                            for st in h.steps:
                                tf_ = getattr(st.detail, "transformedFlow", None)
                                if tf_ is not None:
                                    bsrc = str(tf_.get("srcIp") if isinstance(tf_, dict) else tf_.srcIp)
                    bf.set_snapshot(f"{pfx}-{cls}")
                    exp = snat if snat not in (None,) else f["src"]
                    if snat == "unsupported":
                        natres["ref-unsupported"] += 1
                    elif (bsrc or f["src"]) == exp:
                        natres["agree"] += 1
                    else:
                        natres["DISAGREE"] += 1; natmis.append({**f, "ref_snat": snat, "bf_snat": bsrc})
    report[host] = {"flows": len(flows), "verdicts": {"|".join(k): v for k, v in res.items()}, "unsupported_fencing": dict(unsup_check),
                    "nat": dict(natres), "mismatches": mism[:50], "n_mismatches": len(mism), "nat_mismatches": natmis[:20],
                    "secs": round(time.time() - t0, 1)}
    print(host, json.dumps({k: v for k, v in report[host].items() if k not in ("mismatches", "nat_mismatches")}), flush=True)
    for x in mism[:5] + natmis[:3]:
        print("   MISMATCH", json.dumps(x, default=str)[:400], flush=True)
report["timings"] = log
json.dump(report, open(f"{RESULTS}/validate2-{pfx}-{'_'.join(n[:6] for n in nodes)}.json", "w"), indent=1, default=str)
