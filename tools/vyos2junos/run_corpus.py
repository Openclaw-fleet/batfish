#!/usr/bin/env python3
"""Run a lane-2 kernel/VyOS ground-truth corpus (JSONL) differentially against
(a) the Batfish translation (snapshots <prefix>-{new,est,nat}) and (b) the independent reference evaluator.

usage: run_corpus.py <corpus.jsonl> <render_dir> <snap_prefix> [--tcp-loose 0|1|both|config] [--out f.json]
JSONL fields: gateway, iif ("ethN"|"local"), src, dst, proto, sport, dport, icmp_type, tcp_flags, ct_state,
              verdict, optional snat_src, sha.  Every disagreement is reported; nothing is dropped silently.
"""
import argparse, collections, glob, ipaddress, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bfmeasure import session, measure, RESULTS, WORK
from vyos_ref2 import Ref
from corpus import bf_eval, bf_headers, resolve_auto_src
from vyosmodel import Model, load_commands

ap = argparse.ArgumentParser()
ap.add_argument("corpus"); ap.add_argument("render"); ap.add_argument("prefix")
ap.add_argument("--tcp-loose", default="both"); ap.add_argument("--out")
a = ap.parse_args()
loose = a.tcp_loose if a.tcp_loose in ("both", "config") else int(a.tcp_loose)
NORM = {"accept": "accept", "accepted": "accept", "forward": "accept", "forwarded": "accept", "deliver": "accept",
        "delivered": "accept", "pass": "accept", "drop": "deny", "dropped": "deny", "reject": "deny", "rejected": "deny",
        "deny": "deny", "denied": "deny", "noroute": "noroute", "no_route": "noroute"}


def flags(tf):
    tf = (tf or "").upper().replace(",", "").replace("|", "").replace(" ", "")
    for w, l in (("SYN", "S"), ("ACK", "A"), ("FIN", "F"), ("RST", "R"), ("PSH", "P")):
        tf = tf.replace(w, l)
    return "S" in tf, "A" in tf, set(tf) - {"S", "A"}


nodes = {}
for d in sorted(glob.glob(f"{a.render}/node*")):
    nd = os.path.basename(d)
    side = json.load(open(f"{WORK}/v2/sidecar-{a.prefix}-new/{nd}.json"))
    text = open(f"{d}/vyos-commands.sh").read()
    nodes[nd] = nodes[side.get("host", nd)] = {"nd": nd, "host": side.get("host"), "ifmap": side["ifmap"], "text": text}
bf = session("v2")
refs, models = {}, {}
rows = [json.loads(l) for l in open(a.corpus) if l.strip()]
rep = collections.Counter(); mism = []; log = []
by = collections.defaultdict(list)
for i, r in enumerate(rows):
    g = nodes.get(r["gateway"]) or next((v for k, v in nodes.items() if r["gateway"] in k), None)
    if g is None:
        mism.append({"row": i, "kind": "UNKNOWN_GATEWAY", **r}); continue
    if g["nd"] not in refs:
        refs[g["nd"]] = Ref(g["text"], loose); models[g["nd"]] = refs[g["nd"]].m
    proto = str(r["proto"]).lower()
    syn, ack, other = flags(r.get("tcp_flags")) if proto == "tcp" else (False, False, set())
    ct = (r.get("ct_state") or "auto").lower()
    f = {"iif": r["iif"], "src": r.get("src") or "AUTO", "dst": r["dst"], "proto": proto, "sport": int(r.get("sport") or 0),
         "dport": int(r.get("dport") or 0), "ct": ct, "syn": syn, "ack": ack, "row": i}
    if proto == "icmp":
        f["icmp_type"] = int(r.get("icmp_type", 8)); f["icmp_code"] = int(r.get("icmp_code", 0))
    if other:
        f["unmodeled_flags"] = "".join(sorted(other))
    by[g["nd"]].append((r, f))

with measure(f"corpus {len(rows)} rows", log):
    for nd, items in by.items():
        g = nodes[nd]; ref = refs[nd]; host = g["host"]; ifmap = g["ifmap"]
        for r, f in items:
            f = resolve_auto_src(models[nd], f, ref)
            kv = NORM.get(str(r["verdict"]).lower(), "?" + str(r["verdict"]))
            rv, why, rsnat = ref.verdict(f)
            if f.get("unmodeled_flags"):
                rv, why = "unsupported", f"tcp flags {f['unmodeled_flags']} not in corpus/translator flag model (SYN/ACK only)"
            if rv == "unsupported" or f["ct"] == "related":
                bv, oif = "unsupported", None
            else:
                cls = "est" if f["ct"] == "established" else "new"
                if f["ct"] == "auto":
                    f = dict(f, ct="new")  # first packet: filter verdict is loose-independent (sidecar proof); ref says if not
                bf.set_snapshot(f"{a.prefix}-{cls}")
                bv, oif, disp, _ = bf_eval(bf, host, ifmap, f)
            key = f"kernel={kv}|ref={rv}|batfish={bv}"
            rep[key] += 1
            res = {"row": f["row"], "gateway": host, "flow": {k: f[k] for k in ("iif", "src", "dst", "proto", "sport", "dport", "ct", "syn", "ack")},
                   "kernel": kv, "ref": rv, "ref_why": why, "batfish": bv, "sha": r.get("sha")}
            if rv == "unsupported" or bv == "unsupported":
                res["kind"] = "UNSUPPORTED (explicit, not a pass)"; mism.append(res); continue
            if kv != bv or kv != rv:
                res["kind"] = "MISMATCH"; mism.append(res)
            if r.get("snat_src") and kv == "accept" and f["iif"] != "local":
                bf.set_snapshot(f"{a.prefix}-nat")
                fr = bf.q.traceroute(startLocation=f"@enter({host}[{ifmap[f['iif']]}.0])", headers=bf_headers(f)).answer().frame()
                bsrc = None
                for t in [t for tr in fr["Traces"] for t in tr]:
                    for h in t.hops:
                        for st in h.steps:
                            tf_ = getattr(st.detail, "transformedFlow", None)
                            if tf_ is not None:
                                bsrc = tf_.srcIp
                bsrc = bsrc or f["src"]; rs = rsnat or f["src"]
                ok = (bsrc == r["snat_src"] == rs)
                rep[f"snat|{'agree' if ok else 'DISAGREE'}"] += 1
                if not ok:
                    mism.append({**res, "kind": "SNAT_MISMATCH", "kernel_snat": r["snat_src"], "ref_snat": rs, "batfish_snat": bsrc})
out = {"corpus": a.corpus, "rows": len(rows), "tcp_loose": loose, "summary": dict(rep), "n_mismatch": sum(1 for m in mism if m.get("kind") == "MISMATCH"),
       "n_snat_mismatch": sum(1 for m in mism if m.get("kind") == "SNAT_MISMATCH"),
       "n_unsupported": sum(1 for m in mism if str(m.get("kind", "")).startswith("UNSUP")), "items": mism, "timings": log}
json.dump(out, open(a.out or f"{RESULTS}/corpus-{os.path.basename(a.corpus)}.json", "w"), indent=1, default=str)
print(json.dumps({k: v for k, v in out.items() if k != "items"}, indent=1, default=str))
