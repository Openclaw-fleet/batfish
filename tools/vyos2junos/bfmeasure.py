"""Shared helpers: connect to local Batfish and measure wall time + Java RSS per step."""
import json, os, subprocess, threading, time, contextlib
from pybatfish.client.session import Session

WORK = os.environ.get("BATFISH_WORKDIR", "/tmp/batfish")  # snapshots, sidecars, results
RESULTS = f"{WORK}/results"


def java_pid():
    out = subprocess.check_output(["pgrep", "-f", "org.batfish.allinone.Main"], text=True).split()
    return int(out[0])


def rss_kb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


@contextlib.contextmanager
def measure(label, log):
    pid = java_pid()
    peak = [rss_kb(pid)]
    stop = threading.Event()

    def sample():
        while not stop.is_set():
            peak[0] = max(peak[0], rss_kb(pid))
            time.sleep(0.2)

    t = threading.Thread(target=sample, daemon=True)
    t.start()
    t0 = time.time()
    try:
        yield
    finally:
        stop.set(); t.join()
        rec = {"step": label, "wall_s": round(time.time() - t0, 2),
               "java_rss_peak_mb": round(peak[0] / 1024), "java_rss_end_mb": round(rss_kb(pid) / 1024)}
        log.append(rec)
        print(json.dumps(rec), flush=True)


def session(network):
    bf = Session(host="127.0.0.1")
    bf.set_network(network)
    return bf
