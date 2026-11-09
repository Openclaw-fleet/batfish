#!/usr/bin/env python3
"""PR mode: render base and head offline, translate, and report what changed.

usage: pr_diff.py <repo> <base_ref> <head_ref> [--expect pr_expect.yml] [--classes new,est] [--out dir]

Steps (each timed): git archive -> render-vyos-node-artifacts.py --nodes all -> vyos2junos (new/est)
-> Batfish init -> compareFilters (rule-level: which VyOS rules changed what) -> differentialReachability
(flow-level examples) -> optional expectation check on every changed flow -> markdown summary.
"""
import argparse, collections, json, os, shutil, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yaml
import hset as H
from bfmeasure import session, measure, WORK
from pybatfish.datamodel.flow import HeaderConstraints

ap = argparse.ArgumentParser()
ap.add_argument("repo"); ap.add_argument("base"); ap.add_argument("head")
ap.add_argument("--expect"); ap.add_argument("--base-render"); ap.add_argument("--head-render")
ap.add_argument("--tag"); ap.add_argument("--classes", default="new,est"); ap.add_argument("--out", default=f"{WORK}/pr")
a = ap.parse_args()
log = []
V = sys.executable


def sh(cmd, **kw):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)
    if r.returncode:
        raise SystemExit(f"FAILED: {cmd}\n{r.stdout}\n{r.stderr}")
    return r.stdout


shas = {}
pre = {"base": a.base_render, "head": a.head_render}
for side, ref in (("base", a.base), ("head", a.head)):
    shas[side] = ("render:" + pre[side]) if pre[side] else sh(f"git -C {a.repo} rev-parse {ref}").strip()
tag = a.tag or f"{shas['base'][:9]}..{shas['head'][:9]}"
root = f"{a.out}/{tag}"
os.makedirs(root, exist_ok=True)

for side in ("base", "head"):
    sha = shas[side]
    src, rnd = f"{root}/{side}-src", pre[side] or f"{root}/{side}-render"
    if not pre[side]:
      with measure(f"render {side} {sha[:9]}", log):
        shutil.rmtree(src, ignore_errors=True); os.makedirs(src)
        sh(f"git -C {a.repo} archive {sha} | tar -x -C {src}")
        sh(f"{V} -I {src}/tools/render-vyos-node-artifacts.py --output-dir {rnd} --nodes all --clean")
    with measure(f"translate {side}", log):
        sh(f"{os.path.dirname(os.path.abspath(__file__))}/build_snaps.sh {rnd} pr-{side}")
bf = session("pr")
for side in ("base", "head"):
    for cls in a.classes.split(","):
        with measure(f"init pr-{side}-{cls}", log):
            bf.init_snapshot(f"{WORK}/snap/pr-{side}-{cls}", name=f"pr-{side}-{cls}", overwrite=True)


def origins(side, cls):
    o = {}
    d = f"{WORK}/v2/sidecar-pr-{side}-{cls}"
    for f in os.listdir(d):
        s = json.load(open(f"{d}/{f}"))
        for k, v in s["terms"].items():
            o[(s["host"], k)] = v
    return o


report = {"base": shas["base"], "head": shas["head"], "classes": {}}
for cls in a.classes.split(","):
    ob, oh = origins("base", cls), origins("head", cls)
    with measure(f"compareFilters {cls}", log):
        cf = bf.q.compareFilters(filters="/^(IN|OUT|UNSUP)_/").answer(snapshot=f"pr-head-{cls}", reference_snapshot=f"pr-base-{cls}").frame()
    rows = []
    for _, r in cf.iterrows():
        node, filt = r["Node"], r["Filter_Name"]
        hl = str(r["Line_Content"]).split()[0] if str(r["Line_Content"]) else ""
        bl = str(r["Reference_Line_Content"]).split()[0] if str(r["Reference_Line_Content"]) else ""
        h = oh.get((node, f"{filt}/{hl}"), {}); b = ob.get((node, f"{filt}/{bl}"), {})
        rows.append({"gateway": node, "filter": filt, "head_action": str(r["Line_Action"]), "head_rule": h.get("origin", hl),
                     "base_action": {"accept": "PERMIT", "drop": "DENY", "reject": "DENY"}.get(b.get("action"), "?"),
                     "base_rule": b.get("origin", bl or "(implicit)"),
                     "head_cond": h.get("cond", "")[:220]})
    with measure(f"differentialReachability {cls}", log):
        dr = bf.q.differentialReachability().answer(snapshot=f"pr-head-{cls}", reference_snapshot=f"pr-base-{cls}").frame()
    flows = []
    for _, r in dr.iterrows():
        f = r["Flow"]
        flows.append({"ingress": f"{f.ingressNode}[{f.ingressInterface or 'local'}]", "src": str(f.srcIp), "dst": str(f.dstIp),
                      "proto": str(f.ipProtocol), "dport": f.dstPort, "syn": f.tcpFlagsSyn, "ack": f.tcpFlagsAck,
                      "base": sorted({str(t.disposition) for t in r["Reference_Traces"]}),
                      "head": sorted({str(t.disposition) for t in r["Snapshot_Traces"]})})
    report["classes"][cls] = {"changed_filter_lines": rows, "n_changed_lines": len(rows), "changed_flows": flows, "n_changed_flows": len(flows)}

# expectation check: every changed flow must satisfy the PR's declared intent
if a.expect:
    X = yaml.safe_load(open(a.expect))
    allowed_src = H.ipset(X["changes_only_for_sources"]) if X.get("changes_only_for_sources") else None
    direction = X.get("direction")  # "permit->deny" | "deny->permit" | None
    PERMIT = {"ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK", "NEIGHBOR_UNREACHABLE", "INSUFFICIENT_INFO"}
    viol = []
    for cls, rr in report["classes"].items():
        for f in rr["changed_flows"]:
            b = "permit" if set(f["base"]) & PERMIT else "deny"; h = "permit" if set(f["head"]) & PERMIT else "deny"
            ok = True
            if allowed_src is not None and not H.contains(allowed_src, int(__import__("ipaddress").ip_address(f["src"]))):
                ok = False
            if direction and f"{b}->{h}" != direction:
                ok = False
            if not ok:
                viol.append({**f, "class": cls, "change": f"{b}->{h}"})
        # rule-level: every changed head line must be in the declared scope too (catches cases the flow sample misses)
        for row in rr["changed_filter_lines"]:
            ha, ba = row["head_action"].upper(), row["base_action"].upper()
            hb = "permit" if "PERMIT" in ha else "deny"; bb = "permit" if "PERMIT" in ba else "deny"
            if direction and hb != bb and f"{bb}->{hb}" != direction:
                viol.append({"class": cls, "rule_level": True, "change": f"{bb}->{hb}", **row})
            if row["filter"].startswith("UNSUP_"):
                viol.append({"class": cls, "rule_level": True, "change": "unsupported region changed", **row})
    report["expectation"] = {"file": a.expect, "status": "FAIL" if viol else "PASS", "violations": viol[:30],
                             "intent": X.get("intent")}

report["timings"] = log
json.dump(report, open(f"{root}/pr-diff.json", "w"), indent=1, default=str)

# markdown summary
md = [f"# Batfish PR diff {shas['base'][:9]} → {shas['head'][:9]}", ""]
tot = sum(t["wall_s"] for t in log)
md.append(f"Total wall time {tot:.0f} s (" + ", ".join(f"{t['step']} {t['wall_s']:.1f}s" for t in log) + ")")
md.append("")
if "expectation" in report:
    md.append(f"**Expectation `{os.path.basename(a.expect)}`: {report['expectation']['status']}**: {report['expectation'].get('intent','')}")
    md.append("")
for cls, rr in report["classes"].items():
    md.append(f"## Class `{cls}`: {rr['n_changed_lines']} changed rule lines, {rr['n_changed_flows']} changed flow classes")
    md.append("")
    grp = collections.defaultdict(set)
    for row in rr["changed_filter_lines"]:
        grp[(row["head_rule"].split("=>")[-1].split(">")[-1], row["head_action"], row["base_action"])].add(row["gateway"])
    md.append("| VyOS rule (head) | now | before | gateways |")
    md.append("|---|---|---|---|")
    for (rule, ha, ba), g in sorted(grp.items()):
        md.append(f"| `{rule}` | {ha} | {ba} | {len(g)}: {', '.join(sorted(x.replace('vyos-gw-', 'gw') for x in g))} |")
    md.append("")
    md.append("Example changed flows (one per ingress/disposition change):")
    md.append("")
    for f in rr["changed_flows"][:20]:
        md.append(f"- {f['ingress']} {f['src']}→{f['dst']} {f['proto']}:{f['dport']}: {','.join(f['base'])} → {','.join(f['head'])}")
    md.append("")
open(f"{root}/pr-diff.md", "w").write("\n".join(md) + "\n")
print("\n".join(md))
