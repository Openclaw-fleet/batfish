#!/bin/bash
# usage: build_snaps.sh <render_dir> <out_prefix>
#   -> $BATFISH_WORKDIR/snap/<out_prefix>-{new,est,nat}  (Junos configs + dummy L1 topology)
#   -> $BATFISH_WORKDIR/v2/sidecar-<out_prefix>-<cls>/<node>.json  (term origins, UNSUP regions)
set -euo pipefail
R=$1; P=$2
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${BATFISH_WORKDIR:-/tmp/batfish}"
PY="${PYTHON:-python3}"
mkdir -p "$WORK/v2"
for cls in new est nat; do
  S=$WORK/snap/$P-$cls; rm -rf $S; mkdir -p $S/configs $S/batfish $S/sidecar
  # dummy L1 edge: stops Batfish inferring L3 adjacency between gateways that share 10.10.x.1 subnets
  "$PY" - <<PY
import json; json.dump({"edges":[{"node1":{"hostname":"none-a","interfaceName":"x"},"node2":{"hostname":"none-b","interfaceName":"y"}}]}, open("$S/batfish/layer1_topology.json","w"))
PY
  for d in $R/node*/; do n=$(basename $d); "$PY" -I "$HERE/vyos2junos.py" $d/vyos-commands.sh $S/configs/$n.cfg --cls $cls --sidecar $S/sidecar/$n.json >> $S/build.log; done
  # sidecars live outside configs/ so Batfish does not try to parse them
  rm -rf "$WORK/v2/sidecar-$P-$cls"; mv $S/sidecar "$WORK/v2/sidecar-$P-$cls"
done
