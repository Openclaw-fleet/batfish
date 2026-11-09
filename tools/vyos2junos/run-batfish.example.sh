#!/bin/bash
# How the spike ran the Batfish server (v2026.08.27 allinone bundle, Temurin 25), loopback only.
# BF_HOME holds allinone-bundle.jar + questions/ + log4j2.yaml extracted from
# batfish/batfish@sha256:7909378197c5a3974f2e8180af58cef0ca17b74d1cd9ba39f2d1fddb64737e55
# (allinone-bundle.jar sha256 7552e1380e79379b17e200b80d84c1671f689cb63a0d338678c1c4675157310f).
# Heap: 12g fits a 16 GB host (spike peak RSS 13.3 GB); G1 periodic GC returns idle heap to the OS.
set -euo pipefail
BF_HOME="${BF_HOME:?set BF_HOME}"; JAVA="${JAVA:-java}"; WORK="${BATFISH_WORKDIR:-/tmp/batfish}"
mkdir -p "$WORK/logs" "$WORK/data/containers"
cd "$BF_HOME"
exec "$JAVA" -Xms1g -Xmx12g -XX:-UseCompressedOops \
  -XX:G1PeriodicGCInterval=30000 -XX:MaxHeapFreeRatio=30 -XX:MinHeapFreeRatio=10 \
  -Xlog:gc*:file="$WORK/logs/gc.log":time,uptime:filecount=5,filesize=50m \
  -Dlog4j.configurationFile=log4j2.yaml \
  -cp allinone-bundle.jar org.batfish.allinone.Main \
  -runclient false -loglevel warn \
  -coordinatorargs "-templatedirs questions -containerslocation $WORK/data/containers -workbindhost 127.0.0.1"
