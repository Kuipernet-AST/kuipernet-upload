#!/usr/bin/env python3
"""Hours-long repetition test for Kuipernet Upload with real backends.

The environment (nginx + module, PHP-FPM, Tomcat) is started once and stays up
across load segments, so the same nginx workers are observed for the whole
run. Every SAMPLE_SECONDS the nginx workers' RSS, open descriptors and request
body temp files are appended to soak-samples.jsonl.

  soak.py start NGINX MODULE OUT
  soak.py run   NGINX MODULE OUT --minutes N [--concurrency C]   (repeatable)
  soak.py stop  NGINX MODULE OUT
"""
import json
import os
import random
import re
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_e2e as e  # noqa: E402

SAMPLE_SECONDS = 10


def proc_rss(pid):
    try:
        for line in open("/proc/%d/status" % pid):
            if line.startswith("VmRSS"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def other_rss(pattern):
    total = 0
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                cmd = open("/proc/%s/cmdline" % pid).read()
            except OSError:
                continue
            if pattern in cmd:
                total += proc_rss(int(pid))
    return total


def run(env, minutes, conc):
    blobs = [e.rnd(n, 700 + i) for i, n in enumerate((300000, 1200000, 2500000))]
    normal = [e.build([e.F("t", b"x"), e.U("f[]", "a.tar.gz", b),
                       e.U("f[]", "b.min.js", b[:70000])])[0] for b in blobs]
    truncated = e.build([e.F("t", b"x"), e.U("f", "a.bin", blobs[0])],
                        close=False)[0]
    progress = e.build([e.U("f", "a.bin", blobs[1]),
                        e.F("PHP_SESSION_UPLOAD_PROGRESS", b"probe")])[0]
    badname = e.build([e.U("f[]", "ok.txt", blobs[0]),
                       e.U("f[]", "shell.php.jpg", blobs[0][:5000])])[0]
    slow = e.build([e.U("f", "slow.bin", blobs[0])])[0]

    seg_path = os.path.join(env.out, "soak-segments.jsonl")
    sample_path = os.path.join(env.out, "soak-samples.jsonl")
    prior = 0.0
    if os.path.exists(sample_path):
        for line in open(sample_path):
            prior = json.loads(line)["t"]
    t_start = time.time()
    end = t_start + minutes * 60
    stop = threading.Event()
    counts = {}
    kinds = {}
    unexpected = []
    lock = threading.Lock()

    def sampler():
        with open(sample_path, "a") as f:
            while not stop.is_set():
                s = env.snapshot()
                s["t"] = round(prior + time.time() - t_start, 1)
                s["workers"] = env.workers()
                s["worker_rss_kb"] = [proc_rss(p) for p in s["workers"]]
                s["php_fpm_rss_kb"] = other_rss("php-fpm")
                s["tomcat_rss_kb"] = other_rss("catalina")
                with lock:
                    s["requests_this_segment"] = sum(counts.values())
                f.write(json.dumps(s) + "\n")
                f.flush()
                stop.wait(SAMPLE_SECONDS)

    def client(seed):
        r = random.Random(seed)
        while time.time() < end:
            backend, path = e.TARGETS[r.randrange(2)]
            x = r.random()
            try:
                if x < 0.55:
                    kind, want = "normal h1", (200,)
                    st, _ = e.h1(e.P_FN_BLK, path, r.choice(normal), "soak", wait=60)
                elif x < 0.63:
                    kind, want = "normal h2c", (200,)
                    st, _ = e.h2c(e.P_FN_BLK, path, r.choice(normal), "soak", wait=60)
                elif x < 0.68:
                    kind, want = "normal h2 tls", (200,)
                    st, _ = e.h2c(e.P_TLS_BLK, path, r.choice(normal), "soak",
                                  wait=60, tls=True)
                elif x < 0.72:
                    kind, want = "tls h2: stalled stream + normal stream", ("ok",)
                    res, closed = e.h2_multi(e.P_TLS_CON, [
                        {"tid": "soak", "path": "/c/small", "body": slow,
                         "stall_at": 90000},
                        {"tid": "soak", "path": "/c/unset", "body": normal[0],
                         "piece": 60000, "delay": 0.3}])
                    good = (res[0]["status"] is None and res[0]["done"]
                            and 1.8 <= res[0]["end"] <= 3.5
                            and res[1]["status"] == 200 and not closed)
                    st = "ok" if good else "stream-isolation-failed:%s" % res
                elif x < 0.80:
                    kind, want = "closing boundary missing", (400,)
                    st, _ = e.h1(e.P_FN_BLK, path, truncated, "soak")
                elif x < 0.86:
                    kind, want = "session progress field", (403,)
                    st, _ = e.h1(e.P_FN_BLK, path, progress, "soak")
                elif x < 0.92:
                    kind, want = "denied file name", (403,)
                    st, _ = e.h1(e.P_FN_BLK, path, badname, "soak")
                elif x < 0.97:
                    kind, want = "client abort", (None,)
                    st, _ = e.h1(e.P_FN_BLK, path, r.choice(normal), "soak",
                                 abort_at=r.randrange(1000, 250000))
                else:
                    kind, want = "slow h1", (200,)
                    st, _ = e.h1(e.P_FN_BLK, path, normal[0], "soak", piece=30000,
                                 delay=0.1)
            except Exception as ex:  # noqa: BLE001 - record and continue
                kind, want, st = "client exception", (), "%s" % type(ex).__name__
            with lock:
                counts[str(st)[:40]] = counts.get(str(st)[:40], 0) + 1
                kinds[kind] = kinds.get(kind, 0) + 1
                if st not in want and len(unexpected) < 50:
                    unexpected.append({"kind": kind, "got": str(st)[:300],
                                       "t": round(prior + time.time() - t_start)})

    threading.Thread(target=sampler, daemon=True).start()
    threads = [threading.Thread(target=client, args=(int(prior) * 100 + i,))
               for i in range(conc)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    time.sleep(5)
    stop.set()
    time.sleep(1)
    idle = env.snapshot()
    seg = {"from_t": prior, "minutes": minutes, "concurrency": conc,
           "requests": sum(counts.values()), "outcomes": counts, "kinds": kinds,
           "unexpected_count": sum(v for k, v in counts.items()
                                   if k not in ("200", "400", "403", "None", "ok")),
           "unexpected_examples": unexpected, "idle_after": idle,
           "workers": env.workers()}
    with open(seg_path, "a") as f:
        f.write(json.dumps(seg) + "\n")
    print("SEGMENT", json.dumps({k: seg[k] for k in (
        "from_t", "minutes", "requests", "outcomes", "unexpected_count",
        "idle_after", "workers")}), flush=True)


def main():
    cmd, nginx, module, out = sys.argv[1:5]
    if cmd == "start":
        env = e.Env(nginx, module, out, quiet=True)
        env.start()
        meta = {"versions": env.versions(), "workers": env.workers(),
                "idle_at_start": env.snapshot(), "started": time.time()}
        json.dump(meta, open(os.path.join(out, "soak-meta.json"), "w"), indent=1)
        print("STARTED", json.dumps(meta["idle_at_start"]), meta["workers"])
    elif cmd == "run":
        env = e.Env(nginx, module, out, quiet=True, attach=True)
        minutes = float(sys.argv[sys.argv.index("--minutes") + 1])
        conc = int(sys.argv[sys.argv.index("--concurrency") + 1]) \
            if "--concurrency" in sys.argv else 8
        run(env, minutes, conc)
    elif cmd == "stop":
        env = e.Env(nginx, module, out, quiet=True, attach=True)
        meta = json.load(open(os.path.join(out, "soak-meta.json")))
        meta["workers_at_end"] = env.workers()
        meta["idle_at_end"] = env.snapshot()
        meta["tomcat_stats_end"] = env.tomcat_stats()
        env.stop()
        err = open(env.logs["shield"], errors="replace").read()
        meta["nginx_alerts"] = len(re.findall(r"\[(alert|emerg|crit)\]", err))
        meta["worker_exits_on_signal"] = len(re.findall(r"exited on signal", err))
        meta["shield_warn_lines"] = err.count("upload_shield:")
        rules = {}
        for m in re.finditer(r'"action":"(\w+)","rule":"([\w-]+)"', err):
            rules["%s %s" % m.groups()] = rules.get("%s %s" % m.groups(), 0) + 1
        meta["shield_warn_by_action_rule"] = rules
        other = {}
        for line in err.splitlines():
            if "upload_shield:" not in line:
                m = re.search(r"\[(\w+)\] \d+#\d+: (?:\*\d+ )?(.{0,60})", line)
                if m:
                    key = "%s: %s" % (m.group(1), re.sub(r"\d+", "N", m.group(2)))
                    other[key] = other.get(key, 0) + 1
        meta["other_nginx_log_lines"] = dict(sorted(other.items(),
                                                    key=lambda kv: -kv[1])[:12])
        json.dump(meta, open(os.path.join(out, "soak-meta.json"), "w"), indent=1)
        print("STOPPED", json.dumps({k: meta[k] for k in (
            "workers", "workers_at_end", "idle_at_end", "nginx_alerts",
            "worker_exits_on_signal")}))


if __name__ == "__main__":
    main()
