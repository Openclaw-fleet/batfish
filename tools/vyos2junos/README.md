---
id: tools/batfish
summary: Read this when you need the as-validated #4909 Batfish spike code — the VyOS→Junos translator, the policies.yml expectation checker, PR-mode diff and the corpus runner.
status: design
when: When landing or extending the Batfish engine behind tools/policy-verify, or reproducing a #4909 result.
---

# batfish

> The #4909 spike code, as validated: offline VyOS gateway policy checked by Batfish through an analysis-only Junos translation.

## overview

> Batfish cannot model VyOS firewall, zone or NAT natively, so each rendered `vyos-commands.sh` is compiled into Junos stateless filters that Batfish can reason about.

Design, assumptions (K1–K4), coverage, validation evidence and results are in issue #4909. The integration plan is #4378, and the first finding is #4377. This directory is the code behind those issues. It is kept unchanged except for path handling, so that #4909's numbers stay reproducible.

- [vyosmodel.py](vyosmodel.py) replays `vyos-commands.sh` as a set/delete session. It classifies every config path as MODELED, OUT_OF_SCOPE (with a reason) or UNSUPPORTED.
- [hset.py](hset.py) is exact interval algebra over src/dst/proto/ports/TCP flags.
- [vyos2junos.py](vyos2junos.py) is the translator. It emits one Junos config per gateway and per traffic class (`new`, `est`, `nat`), plus a sidecar JSON with each term's VyOS origin and the UNSUPPORTED regions. Semantics follow vyos-1x `dbde15e2` nftables templates.
- [vyos_ref2.py](vyos_ref2.py) is an independent per-packet reference evaluator that shares only the parser. `tcp_loose` is an explicit input: `0`, `1`, `both` or `config`.
- [gen_expectations.py](gen_expectations.py) and [check_expectations.py](check_expectations.py) derive assertions from `policies.yml`/`zones.yml`/`production.yml` and decide them with `filterLineReachability`. `searchFilters` supplies a witness flow for each failure.
- [pr_diff.py](pr_diff.py) is PR mode: offline render of base and head, translate, `compareFilters` + `differentialReachability`, then an intent check.
- [validate2.py](validate2.py) + [corpus.py](corpus.py) are the differential validation against the reference evaluator. [run_corpus.py](run_corpus.py) diffs a kernel/VyOS ground-truth JSONL corpus against both.
- [build_snaps.sh](build_snaps.sh), [load2.py](load2.py) and [bfmeasure.py](bfmeasure.py) are snapshot build/load helpers with wall-time and Java RSS measurement. [run-batfish.example.sh](run-batfish.example.sh) shows how the spike ran the server.

## interfaces

> A render directory in; Junos snapshots, assertion results and PR-diff markdown out.

- **Inputs:** `tools/render-vyos-node-artifacts.py --output-dir <render> --nodes all` output, and the repo's `vyos/ansible/vars`.
- **Work directory:** `$BATFISH_WORKDIR` (default `/tmp/batfish`) holds `snap/`, `v2/` sidecars, `results/` and `pr/`.
- **Batfish:** a server on `127.0.0.1:9996`, v2026.08.27, pinned `batfish/batfish@sha256:7909378197c5a3974f2e8180af58cef0ca17b74d1cd9ba39f2d1fddb64737e55`, with pybatfish 2026.8.27.3685. Keep the API on loopback.
- **Fixtures:** [fixtures/mutations-099e06bd8.diff](fixtures/mutations-099e06bd8.diff) holds the five injected faults against the 099e06bd8 render, [fixtures/smoke-corpus.jsonl](fixtures/smoke-corpus.jsonl) is in the corpus schema with one deliberately flipped verdict, and [fixtures/pr-4184-intent.yml](fixtures/pr-4184-intent.yml) is the intent file.
- **Tests:** [tests/test_vyos2junos_contracts.py](tests/test_vyos2junos_contracts.py) needs no Batfish. It pins the Batfish-workaround emission contracts and the translator/reference agreement on a fixture gateway.

## gotchas

> A PASS covers only the VyOS gateway layer, and anything the model cannot prove is UNSUPPORTED, not PASS.

- Out of scope: guest ct-firewall nftables, PVE host firewalls, L2 behaviour (anycast `.1`, ARP fence, MAC learning), IPv6 and live drift.
- Junos `tcp-initial` is modelled by Batfish as SYN regardless of ACK, so SYN-only is emitted as `tcp-flags "(syn & !ack)"`.
- Batfish keeps only the last `match source-address` of a NAT rule, so NAT matches use one address-set per side.
- `then source-nat off` is correct for VyOS `exclude`. Batfish treats a matched `source-nat off` as a no-op that ends source-NAT rule evaluation, which is exclude semantics. Do not remove it.
- `filterLineReachability` groups identical filters on a node into one `Sources` entry, `"node: A, B"`. [check_expectations.py](check_expectations.py) splits it.
- Each gateway is analysed in isolation, using a dummy Layer-1 edge, so Batfish does not merge the identical `10.10.x.1` subnets across gateways.
- The heaviest step, the full assertion check, peaked at 13.3 GB Java RSS with `-Xmx12g`. Run one Batfish session at a time on a 16 GB host.
- Not yet validated against booted VyOS. The reference evaluator and the translator share one reading of vyos-1x.

## runbook

> Documentation only — these commands are never executed by this README.

```
render-vyos-node-artifacts.py --output-dir "$R" --nodes all --clean
tools/batfish/build_snaps.sh "$R" cur
python3 -I tools/batfish/load2.py v2 cur-new cur-est cur-nat
python3 -I tools/batfish/gen_expectations.py . "$BATFISH_WORKDIR/expectations.yml"
python3 -I tools/batfish/check_expectations.py "$R" "$BATFISH_WORKDIR/expectations.yml" cur
python3 -I tools/batfish/pr_diff.py . <base> <head> --expect tools/batfish/fixtures/pr-4184-intent.yml
python3 -I tools/batfish/run_corpus.py corpus.jsonl "$R" cur --tcp-loose both
```
