#!/usr/bin/env python3
# demo-feedback.py — end-to-end demo of the feedback & verdict capture loop,
# including verdict steering (supported/contradicted/unverifiable), against
# the local Docker Compose stack.
#
# The loop it walks, in one run:
#
#   1. `alertint drill` fires the flagship burst (planted deploy + 4 alerts)
#      through the production door -> correlator -> LLM triage -> finding.
#   2. `alertint_incident_annotate`        — operator observation, no demotion.
#   3. `alertint_incident_capture_verdict` — three expectations against the same
#      finding, one per grade path:
#        a. confirmation           -> green            (stage 2 replay agrees)
#        b. correction             -> red / synthesis  (evidence was there, the
#                                                       model still concluded it)
#        c. correction             -> red / evidence_selection (the discriminating
#                                                       evidence is not in the pack
#                                                       — no LLM call, plus the
#                                                       unverifiable-series lint;
#                                                       names a Prometheus series
#                                                       the demo can seed later)
#        d. repeat of (c)          -> same verdict version, re-graded, no re-persist
#   4. the same alerts fire again as a NEW incident on the same group key ->
#      its triage prompt recalls (c)'s correction as the governing verdict and
#      the corrected prior renders demoted; the step-2 annotation's free text
#      stays out of the prompt (channel split).
#   5. the same incident fires three more times, each after seeding (c)'s
#      Prometheus series to a different value — proving the ruling follows
#      live evidence rather than trusting the correction as an axiom:
#        5b. series seeded LOW (nearly full) -> ruling=supported, uncapped
#        5c. series seeded HEALTHY           -> ruling=contradicted, the
#                                               correction is NOT adopted
#                                               (the money check)
#        5d. series deleted                  -> ruling=unverifiable, capped
#   6. the audit chain is verified (MCP tool + the in-container CLI).
#
# Checks come in two strengths: hard checks assert deterministic machinery
# (clamps, versioning, backing, channel split, audit) and fail the run; soft
# checks assert model-authored output (ruling strings, finding prose, graded
# replays) and print WARN on a miss — expected LLM ambiguity, never an exit 1.
#
# Everything is written through the real MCP HTTP transport (initialize ->
# tools/call), i.e. exactly what a coding agent does — no in-process shortcuts.
#
# Usage:
#   task demo:feedback                     # the whole thing (starts the stack)
#   task demo:feedback -- --reset          # wipe containers AND volumes first
#   task demo:feedback -- --skip-stack     # use the stack that is already up
#   task demo:feedback -- --skip-drill --incident inc-...   # re-run the write-back
#                                                             steps on one incident
#   task demo:feedback -- --base-config docker/agent.config.local.yaml
#                                          # derive the demo config from your own
#                                          # (inherits Slack, Grafana Cloud, …)
#
# Requires: docker, python3, a built ./bin/alertint (task build), and .env with
# ALERTINT_WEBHOOK_TOKEN / ALERTINT_MCP_TOKEN / ALERTINT_CHANGES_WEBHOOK_TOKEN /
# ANTHROPIC_API_KEY. Triage and the two graded replays are real LLM calls.

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BASE_CONFIG = REPO / "docker" / "agent.config.yaml"
DEMO_CONFIG = REPO / "docker" / "agent.config.demo.local.yaml"
COMPOSE = [
    "docker", "compose",
    "-f", "docker/docker-compose.yaml",
    "-f", "docker/docker-compose.build.yaml",
    "--env-file", ".env",
]

# Demo-tuned knobs, both purely about wall-clock:
#   window_seconds        — how long the correlator collects before triage.
#   attach_window_minutes — how long a re-fire on the same group key collapses
#                           into the open incident instead of minting a new one.
#                           Step 4 needs a NEW incident on the SAME key, so the
#                           demo shortens the window instead of waiting 30m.
DEMO_WINDOW_SECONDS = 30
DEMO_ATTACH_MINUTES = 1

BOLD, DIM, RED, GREEN, YELLOW, CYAN, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[0m"
)
if os.environ.get("NO_COLOR"):
    BOLD = DIM = RED = GREEN = YELLOW = CYAN = RESET = ""

CHECKS = []
RECAP = []  # one line per incident the run created: (short id, what it demonstrated)


def recap(line):
    RECAP.append(line)


def slack_configured(base):
    """Whether the base config wires the Slack notifier (an uncommented
    `slack:` key). Purely for narration — the demo runs the same either way,
    findings just land on stdout instead of a channel."""
    try:
        return bool(re.search(r"(?m)^\s*slack:", base.read_text()))
    except OSError:
        return False


# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------

def step(n, title):
    print(f"\n{BOLD}{CYAN}━━ step {n} — {title}{RESET}")


def info(msg):
    print(f"   {msg}")


def dim(msg):
    print(f"{DIM}   {msg}{RESET}")


def check(name, expected, actual, passed, soft=False):
    """A hard check (default) asserts deterministic machinery — clamps,
    versioning, backing, channel split, audit — and FAILs the run. A soft
    check (soft=True) asserts model-authored output (a ruling string, finding
    prose, a graded replay); a miss there is expected LLM ambiguity, so it
    prints WARN and never fails the run."""
    if passed:
        mark = f"{GREEN}PASS{RESET}"
    elif soft:
        mark = f"{YELLOW}WARN{RESET}"
    else:
        mark = f"{RED}FAIL{RESET}"
    CHECKS.append((name, expected, actual, passed, soft))
    print(f"   [{mark}] {name}: expected {expected}, got {actual}")
    if not passed and soft:
        dim("        soft check: this asserts LLM-authored output — ambiguity is expected here")


def die(msg):
    print(f"\n{RED}demo: {msg}{RESET}", file=sys.stderr)
    sys.exit(1)


def blob(label, value, limit=600):
    text = value if isinstance(value, str) else json.dumps(value, indent=2, default=str)
    if len(text) > limit:
        text = text[:limit] + " …"
    print(f"{DIM}   {label}: {text}{RESET}")


# ---------------------------------------------------------------------------
# MCP over streamable HTTP — initialize once, then tools/call
# ---------------------------------------------------------------------------

class MCPClient:
    def __init__(self, endpoint, token, timeout=240):
        self.endpoint = endpoint
        self.token = token
        self.timeout = timeout
        self.session_id = None
        self._next_id = 1

    def _post(self, method, params):
        body = json.dumps({
            "jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params,
        }).encode()
        self._next_id += 1
        req = urllib.request.Request(self.endpoint, data=body, method="POST")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        if self.session_id:
            req.add_header("Mcp-Session-Id", self.session_id)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode()
                headers = resp.headers
        except urllib.error.HTTPError as e:
            die(f"mcp {method}: http {e.code}: {e.read().decode()[:300]}")
        except urllib.error.URLError as e:
            die(f"mcp {method}: {e}")
        payload = _decode_rpc(raw)
        if "error" in payload:
            die(f"mcp {method}: rpc error {payload['error']}")
        return payload.get("result", {}), headers

    def initialize(self):
        result, headers = self._post("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "alertint-demo-feedback", "version": "1"},
        })
        sid = headers.get("Mcp-Session-Id")
        if sid:
            self.session_id = sid
        return result

    def call(self, name, args):
        result, _ = self._post("tools/call", {"name": name, "arguments": args})
        content = result.get("content") or []
        if not content:
            die(f"mcp {name}: empty tool result")
        text = content[0].get("text", "")
        if result.get("isError"):
            return {"_error": text}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"_text": text}


def _decode_rpc(raw):
    """The server may answer a POST as plain JSON or as an SSE frame."""
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        return json.loads(stripped)
    for line in stripped.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    die(f"could not decode MCP response: {raw[:300]}")


# ---------------------------------------------------------------------------
# stack lifecycle
# ---------------------------------------------------------------------------

def write_demo_config(base):
    """Derive the demo config from a base config: same connectors, two timing
    knobs shortened. *.local.yaml is gitignored."""
    if not base.exists():
        die(f"base config {base} does not exist")
    src = base.read_text()
    out, n = re.subn(r"(?m)^(\s*window_seconds:\s*)\d+", rf"\g<1>{DEMO_WINDOW_SECONDS}", src, count=1)
    if n != 1:
        die(f"could not find correlator.window_seconds in {base}")
    if re.search(r"(?m)^memory:", out):
        die(f"{base} already defines memory: — set attach_window_minutes there instead")
    out += (
        "\n# ── demo overrides (written by scripts/demo-feedback.py) ─────────────────\n"
        "# A re-fire on the same group key collapses into the open incident while it\n"
        "# is inside this window. The demo needs a NEW incident on the SAME key to\n"
        "# show operator recall, so it shortens the window instead of waiting 30m.\n"
        "memory:\n"
        f"  attach_window_minutes: {DEMO_ATTACH_MINUTES}\n"
    )
    DEMO_CONFIG.write_text(out)
    info(f"wrote {DEMO_CONFIG.relative_to(REPO)} from {base.relative_to(REPO)} "
         f"(window {DEMO_WINDOW_SECONDS}s, attach window {DEMO_ATTACH_MINUTES}m)")


def mounted_config():
    """Which config file the running agent container has mounted, or None."""
    proc = subprocess.run(
        ["docker", "inspect", "-f",
         '{{range .Mounts}}{{.Destination}}={{.Source}}{{"\\n"}}{{end}}', "alertint-agent"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        dest, _, source = line.partition("=")
        if dest == "/etc/alertint/config.yaml" and source:
            return Path(source).name
    return None


def compose(args, env, check_rc=True):
    proc = subprocess.run(COMPOSE + args, cwd=REPO, env=env)
    if check_rc and proc.returncode != 0:
        die(f"docker compose {' '.join(args)} failed")


def wait_healthy(webhook_port, timeout=180):
    url = f"http://127.0.0.1:{webhook_port}/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(2)
    die(f"agent did not become healthy at {url} within {timeout}s")


# ---------------------------------------------------------------------------
# alert firing (step 4 replay — the drill owns step 1)
# ---------------------------------------------------------------------------

def post_json(url, token, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        die(f"POST {url}: http {e.code}: {e.read().decode()[:300]}")
    except urllib.error.URLError as e:
        die(f"POST {url}: {e}")


PUSHGATEWAY = "http://127.0.0.1:9091"
DEMO_SERIES = "drill_checkout_pvc_available_percent"
# The seeded series must be indistinguishable from real pod-level storage
# telemetry, or the triage model (correctly) audits its provenance and refuses
# to rule on it: an earlier seed pushed under job="alertint_demo_steering" with
# no labels was ruled "unverifiable — generic pushgateway jobs, not pod-level
# storage data" DESPITE carrying the supporting value. job comes from the push
# path (pushgateway overrides any job label in the body); the kubelet-shaped
# pvc/namespace labels ride through honor_labels.
SEED_JOB = "kubelet"
SEED_LABELS = '{namespace="checkout",persistentvolumeclaim="checkout-logs-pvc"}'


def push_gauge(series, value):
    """Seed one gauge into the dev-stack pushgateway (Prometheus scrapes it
    with honor_labels). value ≈ 3 reads as 'nearly full' (supports the PVC
    correction); ≈ 95 reads as healthy (contradicts it)."""
    body = f"# TYPE {series} gauge\n{series}{SEED_LABELS} {value}\n".encode()
    req = urllib.request.Request(
        f"{PUSHGATEWAY}/metrics/job/{SEED_JOB}", data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        die(f"pushgateway seed failed: {e}")


def delete_gauge():
    req = urllib.request.Request(
        f"{PUSHGATEWAY}/metrics/job/{SEED_JOB}", method="DELETE")
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass  # absent group is fine — that IS the unverifiable state


def refire(incident, webhook_port, token, salt):
    """Fire the incident's own alerts again with fresh fingerprints — a new
    firing episode of the same failure, same group key."""
    now = datetime.now(timezone.utc)
    alerts = []
    for i, a in enumerate(incident["alerts"]):
        fp = hashlib.sha256(f"{salt}:{a['labels'].get('alertname', i)}:{i}".encode()).hexdigest()[:16]
        alerts.append({
            "status": "firing",
            "labels": a["labels"],
            "annotations": a.get("annotations") or {},
            "startsAt": now.isoformat().replace("+00:00", "Z"),
            "fingerprint": fp,
        })
    payload = {
        "version": "4",
        "groupKey": incident["group_key"],
        "status": "firing",
        "receiver": "alertint-demo",
        "groupLabels": {},
        "commonLabels": {},
        "commonAnnotations": {},
        "externalURL": "",
        "alerts": alerts,
    }
    status, _ = post_json(f"http://127.0.0.1:{webhook_port}/webhook/alertmanager", token, payload)
    return status, len(alerts)


# ---------------------------------------------------------------------------
# incident helpers
# ---------------------------------------------------------------------------

def latest_drill_incident(mcp):
    rows = mcp.call("alertint_list_incidents", {"limit": 25}).get("incidents", [])
    drills = [r for r in rows if r.get("drill") and r.get("status") == "analyzed"]
    if not drills:
        return None
    drills.sort(key=lambda r: r["created_at"], reverse=True)
    return drills[0]


def poll_new_incident(mcp, group_key, seen_ids, timeout, interval=5):
    """Poll until a NEW analyzed incident shows up on group_key — "new" meaning
    its id is not in seen_ids, the full set of every incident already known on
    this group key (not just the single most-recently-fired one). A same-key
    incident history accumulates fast across steps 5/5b/5c/5d (and can predate
    this run entirely on a `--skip-stack --skip-drill` reuse) — excluding only
    the last id would let an OLDER analyzed incident on the same key satisfy
    "not excluded" and be returned as if it were the fresh triage, silently."""
    deadline = time.time() + timeout
    seen_status = None
    while time.time() < deadline:
        rows = mcp.call("alertint_list_incidents", {"limit": 25}).get("incidents", [])
        for r in rows:
            if r["group_key"] == group_key and r["id"] not in seen_ids:
                if r["status"] == "analyzed":
                    return r, None
                seen_status = r["status"]
        time.sleep(interval)
    return None, seen_status


def refire_and_wait(mcp, inc, last_id, seen_ids, webhook_port, token, salt, timeout):
    """Wait out the recurrence-collapse window on the most recently fired
    incident (last_id, used only to read its last_alert_at), re-fire inc's
    alerts with a fresh salt, then poll for the resulting NEW analyzed
    incident — new meaning not in seen_ids (see poll_new_incident) — the
    shared refire-and-poll shape the steering phases (5b/5c/5d) each need once
    per seeded value. Callers must add the returned incident's id to seen_ids
    before the next phase."""
    last = mcp.call("alertint_get_incident", {"incident_id": last_id})
    last_alert = datetime.fromisoformat(last["last_alert_at"].replace("Z", "+00:00"))
    ready_at = last_alert + timedelta(minutes=DEMO_ATTACH_MINUTES, seconds=15)
    wait = (ready_at - datetime.now(timezone.utc)).total_seconds()
    if wait > 0:
        info(f"waiting {int(wait)}s for the collapse window to close")
        time.sleep(wait)
    refire(inc, webhook_port, token, salt=salt)
    return poll_new_incident(mcp, inc["group_key"], seen_ids, timeout)


# ---------------------------------------------------------------------------
# the demo
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="AlertINT feedback & verdict capture + steering demo")
    ap.add_argument("--reset", action="store_true", help="docker compose down -v first (clean slate)")
    ap.add_argument("--skip-stack", action="store_true", help="do not touch docker compose; use what is running")
    ap.add_argument("--skip-drill", action="store_true", help="do not fire a drill; reuse an existing drill incident")
    ap.add_argument("--incident", default="", help="incident id to write back to (implies --skip-drill)")
    ap.add_argument("--skip-recall", action="store_true", help="stop after the write-back steps (no second incident)")
    ap.add_argument("--base-config", default=str(BASE_CONFIG.relative_to(REPO)),
                    help="config the demo config is derived from (default docker/agent.config.yaml; "
                         "point at your own to inherit Slack, Grafana Cloud, …)")
    ap.add_argument("--triage-timeout", type=int, default=210, help="seconds to wait for a triage verdict (default 210)")
    args = ap.parse_args()

    # Line-buffer stdout: the drill subprocess writes straight to the fd, so a
    # block-buffered parent would print its own steps out of order (or only at
    # exit) whenever the output is piped or redirected.
    sys.stdout.reconfigure(line_buffering=True)

    env = dict(os.environ)
    for key in ("ALERTINT_WEBHOOK_TOKEN", "ALERTINT_MCP_TOKEN", "ALERTINT_CHANGES_WEBHOOK_TOKEN", "ANTHROPIC_API_KEY"):
        if not env.get(key):
            die(f"{key} is not set — run this through `task demo:feedback` (it loads .env)")
    webhook_port = env.get("ALERTINT_WEBHOOK_PORT", "9911")
    mcp_port = env.get("ALERTINT_MCP_PORT", "9912")
    env["ALERTINT_CONFIG_FILE"] = f"./{DEMO_CONFIG.name}"

    binary = REPO / "bin" / "alertint"
    if not binary.exists():
        die("./bin/alertint is missing — run `task build` first")

    base_path = Path(args.base_config) if Path(args.base_config).is_absolute() else REPO / args.base_config
    slack_on = slack_configured(base_path)

    print(f"{BOLD}AlertINT — feedback & verdict capture + steering end-to-end demo{RESET}")
    dim(f"MCP http://127.0.0.1:{mcp_port}/mcp · receivers http://127.0.0.1:{webhook_port}")
    print()
    info("What this run shows, start to finish: a synthetic incident is triaged by the")
    info("LLM, then an operator (played by this script, over the real MCP transport)")
    info("annotates the finding, confirms it, and finally CORRECTS it — \"the real cause")
    info("was a full PVC, and the evidence for that isn't even in the pack\". The same")
    info("failure then re-fires four times to prove what that correction does next:")
    info("it is recalled, tested against live Prometheus data, and adopted, rejected,")
    info("or confidence-capped strictly according to what the data says.")
    print()
    if slack_on:
        info(f"{BOLD}Heads-up for your Slack channel{RESET}: this run produces FIVE separate")
        info("incident threads for the same failure group — the original drill plus one per")
        info("re-fire phase. That is deliberate, not alert spam: each phase needs its own")
        info("triage run under a different live-evidence state, and every triage is its own")
        info("incident with its own thread. A recap at the end maps each thread to what it")
        info("proved.")
    else:
        info("Slack is not configured in this base config — each triage prints its finding")
        info("to the agent's stdout instead (follow with: task docker:logs). Five findings")
        info("for the same failure group is deliberate: one per demo phase.")

    # ── step 0 — stack ──────────────────────────────────────────────────────
    step(0, "local stack")
    write_demo_config(base_path)
    if args.skip_stack:
        info("--skip-stack: assuming the compose stack is already running")
        mounted = mounted_config()
        if mounted and mounted != DEMO_CONFIG.name:
            info(f"{YELLOW}note{RESET}: the running agent mounts {mounted}, not {DEMO_CONFIG.name}")
            if not args.skip_recall:
                args.skip_recall = True
                info(f"      step 5 (recall) needs the demo config's {DEMO_ATTACH_MINUTES}m attach window — "
                     "a re-fire under a longer window collapses into the open incident instead of")
                info("      minting a new one, so recall is skipped. Re-run without --skip-stack to include it.")
    else:
        if args.reset:
            info("wiping containers and volumes (--reset)")
            compose(["down", "-v"], env, check_rc=False)
        info("starting the stack (agent built from the working tree)")
        compose(["up", "-d", "--build"], env)
    wait_healthy(webhook_port)
    info(f"{GREEN}agent healthy{RESET} — follow it in another shell with: task docker:logs")

    mcp = MCPClient(f"http://127.0.0.1:{mcp_port}/mcp", env["ALERTINT_MCP_TOKEN"])
    mcp.initialize()

    # ── step 1 — incident with a finding ────────────────────────────────────
    step(1, "alerts → correlation → LLM triage (alertint drill)")
    if args.incident:
        incident_id = args.incident
    elif args.skip_drill:
        row = latest_drill_incident(mcp)
        if not row:
            die("no analyzed drill incident found — drop --skip-drill")
        incident_id = row["id"]
        info(f"reusing drill incident {incident_id}")
    else:
        proc = subprocess.run(
            [str(binary), "drill", "--config", str(DEMO_CONFIG.relative_to(REPO)), "--scenario", "flagship"],
            cwd=REPO, env=env,
        )
        if proc.returncode != 0:
            die("alertint drill failed")
        row = latest_drill_incident(mcp)
        if not row:
            die("the drill fired but no analyzed drill incident is visible over MCP")
        incident_id = row["id"]

    inc = mcp.call("alertint_get_incident", {"incident_id": incident_id})
    if "_error" in inc:
        die(f"alertint_get_incident: {inc['_error']}")
    finding = inc.get("finding") or {}
    annotations_before = len(inc.get("annotations") or [])
    check("incident has a finding to grade", "non-empty finding", "present" if finding else "absent", bool(finding))
    info(f"incident {BOLD}{incident_id}{RESET} · group {inc['group_key']} · status {inc['status']}")
    blob("root cause", inc.get("root_cause", ""))
    blob("confidence", inc.get("confidence", ""))
    recap(f"{incident_id[:8]} · the drill triage — the finding every later step grades and steers "
          f"(confidence {inc.get('confidence')})")

    # ── step 2 — annotate ───────────────────────────────────────────────────
    step(2, "alertint_incident_annotate — an observation (context only, no demotion)")
    res = mcp.call("alertint_incident_annotate", {
        "incident_id": incident_id,
        "kind": "observation",
        "note": "Checked with the on-call: the checkout rollout is behind a canary, "
                "so blast radius stayed inside the drill cluster.",
    })
    blob("result", res)
    check("observation stored, nothing demoted", "demoted=False", f"demoted={res.get('demoted')}",
          res.get("demoted") is False and res.get("annotation_id"))

    # ── step 3a — confirmation → green ──────────────────────────────────────
    step("3a", "alertint_incident_capture_verdict — confirmation (expect green)")
    dim("the operator agrees with triage; stage 2 replays the whole pipeline over frozen inputs")
    res = mcp.call("alertint_incident_capture_verdict", {
        "incident_id": incident_id,
        "verdict": "confirmation",
        "expectation": {
            "cause_alert": "DrillCheckoutPodCrashLooping",
            "must_mention": ["checkout"],
            "must_not_conclude": ["network partition"],
        },
        "note": "Confirmed on the bridge: the checkout rollout is the cause.",
        "cause_category": "bad-deploy",
    })
    blob("result", res)
    check("confirmation grades green", "grade=green", f"grade={res.get('grade')} layer={res.get('layer', '-')}",
          res.get("grade") == "green", soft=True)  # stage-2 replay is a real LLM call
    v1 = res.get("version")

    # ── step 3b — correction → synthesis red ────────────────────────────────
    step("3b", "alertint_incident_capture_verdict — correction (expect red / synthesis)")
    dim("the operator says it was NOT the deploy; the evidence is in the pack, so a red here")
    dim("points at the prompt/hint layer, not at evidence selection. widen_queries freezes a live")
    dim("PromQL result into the record first.")
    res = mcp.call("alertint_incident_capture_verdict", {
        "incident_id": incident_id,
        "verdict": "correction",
        "expectation": {
            "must_mention": ["queue"],
            "must_not_conclude": ["deploy"],
        },
        "note": "Not the deploy — the order-queue consumers were already backing up "
                "before the rollout; the rollout only made it visible.",
        # Scoped on purpose: widen exprs are merged forward into every later
        # steering round, and a bare `up` freezes the dev stack's whole target
        # list (pushgateway + prometheus) into the prompt — enough for the
        # model to deduce the seeded pvc series is a pushed gauge and distrust
        # it. Real deployments aren't two-target, the demo shouldn't look it.
        "widen_queries": ['up{job="prometheus"}'],
        "cause_category": "queue-backlog",
    })
    blob("result", res)
    check("correction grades red at the synthesis layer", "grade=red layer=synthesis",
          f"grade={res.get('grade')} layer={res.get('layer', '-')}",
          res.get("grade") == "red" and res.get("layer") == "synthesis",
          soft=True)  # red-vs-green here hangs on what the LLM replay concludes
    check("capture minted a new verdict version", f"version>{v1}", f"version={res.get('version')}",
          isinstance(res.get("version"), int) and isinstance(v1, int) and res["version"] > v1)

    # ── step 3c — correction → evidence-selection red ───────────────────────
    step("3c", "alertint_incident_capture_verdict — correction (expect red / evidence_selection)")
    dim("the discriminating evidence is nowhere in the pack, so the grade stops before the LLM:")
    dim("the fix is a rule/check, not a prompt. The unverifiable-series lint warns too.")
    exp_c = {
        "cause_alert": "KubePersistentVolumeFillingUp",
        "cause_series": [DEMO_SERIES],
        "must_mention": ["checkout-logs-pvc"],
        "must_not_conclude": ["memory leak"],
    }
    res = mcp.call("alertint_incident_capture_verdict", {
        "incident_id": incident_id,
        "verdict": "correction",
        "expectation": exp_c,
        "note": "Real cause was the checkout-logs-pvc filling up; nothing in the pack could show it.",
    })
    blob("result", res)
    check("missing evidence grades red at the evidence-selection layer", "grade=red layer=evidence_selection",
          f"grade={res.get('grade')} layer={res.get('layer', '-')}",
          res.get("grade") == "red" and res.get("layer") == "evidence_selection")
    check("unverifiable cause series warned", "a 'can never go green' warning",
          f"{len(res.get('warnings') or [])} warning(s)",
          any("never go green" in w for w in (res.get("warnings") or [])))
    v3 = res.get("version")

    # ── step 3d — repeat → re-grade, no re-persist ──────────────────────────
    step("3d", "repeat the same capture — re-grades without re-persisting")
    res = mcp.call("alertint_incident_capture_verdict", {
        "incident_id": incident_id,
        "verdict": "correction",
        "expectation": exp_c,
        "note": "Real cause was the checkout-logs-pvc filling up; nothing in the pack could show it.",
    })
    blob("result", res)
    check("unchanged expectation keeps the verdict version", f"version={v3}", f"version={res.get('version')}",
          res.get("version") == v3)

    # ── what the incident looks like now ────────────────────────────────────
    step(4, "the write-back on the incident itself (read back over MCP)")
    inc = mcp.call("alertint_get_incident", {"incident_id": incident_id})
    anns = inc.get("annotations") or []
    blob("annotations", [f"{a['kind']}: {a['note'][:80]}" for a in anns])
    blob("latest verdict", inc.get("verdict"))
    added = len(anns) - annotations_before
    check("every write-back landed on the incident", "4 new annotations",
          f"{added} added ({len(anns)} total)", added == 4)
    check("incident carries the latest verdict", "kind=correction", f"kind={(inc.get('verdict') or {}).get('kind')}",
          (inc.get("verdict") or {}).get("kind") == "correction")

    if args.skip_recall:
        return summarize(env)

    # ── step 5 — recall into the next incident ──────────────────────────────
    step(5, "the same failure happens again — does the correction come back?")
    dim("from here on, each phase re-fires the SAME four alerts as a fresh firing episode:")
    dim("same failure group, new incident, new Slack thread (or stdout finding). That is")
    dim("the mechanism, not a bug — every phase needs its own triage run under a different")
    dim("Prometheus state, and each triage is its own incident.")
    # seen_ids is every incident id already on this group key, BEFORE this run's
    # first re-fire — not just incident_id. A single-id exclude filter would let
    # an older same-key incident (e.g. a leftover from a prior --skip-stack run,
    # or the original drill incident once more incidents accumulate below) match
    # "not excluded" and be handed back as if it were the fresh triage. Every
    # phase below (5, 5b, 5c, 5d) adds its own new incident's id before the next
    # poll, so "new" always means "never seen on this key across this whole run".
    baseline_rows = mcp.call("alertint_list_incidents", {"limit": 25}).get("incidents", [])
    seen_ids = {r["id"] for r in baseline_rows if r["group_key"] == inc["group_key"]}
    last_alert = datetime.fromisoformat(inc["last_alert_at"].replace("Z", "+00:00"))
    ready_at = last_alert + timedelta(minutes=DEMO_ATTACH_MINUTES, seconds=15)
    wait = (ready_at - datetime.now(timezone.utc)).total_seconds()
    if wait > 0:
        info(f"waiting {int(wait)}s for the {DEMO_ATTACH_MINUTES}m recurrence-collapse window to close, "
             "so the re-fire becomes a NEW incident instead of an occurrence")
        time.sleep(wait)
    status, n = refire(inc, webhook_port, env["ALERTINT_WEBHOOK_TOKEN"], salt=f"demo-recall:{incident_id}")
    info(f"re-fired {n} alerts on group {inc['group_key']} with fresh fingerprints (HTTP {status})")
    info(f"waiting for the correlation window + triage (up to {args.triage_timeout}s)…")
    row2, last_status = poll_new_incident(mcp, inc["group_key"], seen_ids, args.triage_timeout)
    if not row2:
        check("re-fire produced a second analyzed incident", "status=analyzed",
              f"status={last_status or 'none'}", False)
        return summarize(env)
    info(f"second incident {BOLD}{row2['id']}{RESET} analyzed")
    seen_ids.add(row2["id"])

    pack = mcp.call("alertint_get_evidence_pack", {"incident_id": row2["id"]})
    memory = ((pack.get("enrichment") or {}).get("memory") or {})
    governing = memory.get("governing_verdict") or {}
    blob("memory tier rendered into the triage prompt", {
        "rung": memory.get("rung"),
        "governing_verdict": governing,
        "weak": [{"incident_id": w.get("incident_id"), "operator_superseded": w.get("operator_superseded")}
                 for w in (memory.get("weak") or [])],
        "strong": (memory.get("strong") or {}).get("incident_id"),
    }, limit=1200)
    check("governing verdict recalled into the new triage", "kind=correction",
          f"kind={governing.get('kind', '-')}", governing.get("kind") == "correction")
    # prompt purity (D5): free-text annotation notes must NOT reach the prompt
    memory_json = json.dumps(memory)
    leaked = "canary" in memory_json  # the step-2 observation's distinctive word
    check("annotation text absent from the triage prompt (channel split)",
          "no note text in memory section", "leaked" if leaked else "absent", not leaked)
    corrected_prior = [w for w in (memory.get("weak") or []) if w.get("operator_superseded")]
    check("corrected prior finding demoted out of strong recall", "prior marked operator_superseded",
          f"{len(corrected_prior)} demoted prior(s)", len(corrected_prior) >= 1)

    inc2 = mcp.call("alertint_get_incident", {"incident_id": row2["id"]})
    blob("new finding root cause", inc2.get("root_cause", ""))
    blob("new finding confidence", inc2.get("confidence", ""))
    dim("this recall's own finding runs with the governing correction's series not yet seeded, so it")
    dim("is unverifiable-capped by design — steps 5b/5c/5d below seed that series deliberately")
    recap(f"{row2['id'][:8]} · recall — the correction comes back as the governing verdict; its "
          f"series is not seeded yet, so adoption is capped (confidence {inc2.get('confidence')})")

    # ── step 5b — steering: supported ──────────────────────────────────────
    step("5b", "steering — series seeded LOW: ruling must be SUPPORTED, adoption uncapped")
    dim("the operator's claimed series now EXISTS in Prometheus and shows the claimed state")
    dim("(3% free — nearly full). The triage must notice: expected ruling is supported,")
    dim("which lifts the confidence cap. The ruling itself is the model's judgment call.")
    push_gauge(DEMO_SERIES, 3)
    info(f"seeded {DEMO_SERIES}=3 (pvc nearly full) — waiting one Prometheus scrape…")
    time.sleep(20)
    seed_low = mcp.call("prometheus_query", {"expr": DEMO_SERIES}).get("result") or []
    check("seed reached Prometheus before the re-fire", "≥1 series",
          f"{len(seed_low)} series", len(seed_low) >= 1)
    row_s, last = refire_and_wait(mcp, inc, row2["id"], seen_ids, webhook_port,
                                  env["ALERTINT_WEBHOOK_TOKEN"], f"demo-supported:{incident_id}", args.triage_timeout)
    if not row_s:
        check("supported-path incident analyzed", "analyzed", last or "none", False)
        return summarize(env)
    seen_ids.add(row_s["id"])
    inc_s = mcp.call("alertint_get_incident", {"incident_id": row_s["id"]})
    oh = inc_s.get("operator_history") or {}
    steering_s = ((mcp.call("alertint_get_evidence_pack", {"incident_id": row_s["id"]})
                   .get("enrichment") or {}).get("verification") or {}).get("operator_ruling") or {}
    blob("ruling", steering_s)
    ruling_s = steering_s.get("ruling")
    check("ruling is supported", "ruling=supported", f"ruling={ruling_s or '-'}",
          ruling_s == "supported", soft=True)  # the ruling string is the model's judgment
    if ruling_s == "supported":
        # uncapped is the *expected* outcome, but the exact confidence is
        # model-chosen — a supported ruling merely lifts the deterministic cap
        check("supported adoption is uncapped", "confidence > 0.6",
              f"confidence={inc_s.get('confidence')}", (inc_s.get("confidence") or 0) > 0.6,
              soft=True)
    else:
        # the model didn't rule supported, so the deterministic clamp MUST
        # have held the confidence at or under the cap — that part is code,
        # not judgment, and a miss is a real failure
        check("non-supported ruling keeps the deterministic confidence cap", "confidence <= 0.6",
              f"confidence={inc_s.get('confidence')} (ruling={ruling_s or '-'})",
              ruling_s == "contradicted" or (inc_s.get("confidence") or 1) <= 0.6)
    check("card payload carries governing verdict", "operator_history.state=history",
          f"state={oh.get('state', '-')}", oh.get("state") == "history")
    recap(f"{row_s['id'][:8]} · seeded low (3% free) — ruling={ruling_s or 'absent'}, "
          f"confidence {inc_s.get('confidence')}")

    # ── step 5c — steering: contradicted (the money check) ─────────────────
    step("5c", "steering — series seeded HEALTHY: ruling must be CONTRADICTED, correction NOT adopted")
    dim("same series, but now it reads 95% free — healthy. If steering treated the operator")
    dim("as an axiom, the model would still blame the PVC; instead the ruling must flip to")
    dim("contradicted and the finding must NOT adopt the corrected cause.")
    push_gauge(DEMO_SERIES, 95)
    time.sleep(20)
    seed_healthy = mcp.call("prometheus_query", {"expr": DEMO_SERIES}).get("result") or []
    check("seed reached Prometheus before the re-fire", "≥1 series",
          f"{len(seed_healthy)} series", len(seed_healthy) >= 1)
    row_c, last = refire_and_wait(mcp, inc, row_s["id"], seen_ids, webhook_port,
                                  env["ALERTINT_WEBHOOK_TOKEN"], f"demo-contradicted:{incident_id}", args.triage_timeout)
    if not row_c:
        check("contradicted-path incident analyzed", "analyzed", last or "none", False)
        return summarize(env)
    seen_ids.add(row_c["id"])
    inc_c = mcp.call("alertint_get_incident", {"incident_id": row_c["id"]})
    steering_c = ((mcp.call("alertint_get_evidence_pack", {"incident_id": row_c["id"]})
                   .get("enrichment") or {}).get("verification") or {}).get("operator_ruling") or {}
    blob("ruling", steering_c)
    check("MONEY CHECK — steering is not an axiom: healthy series contradicts the correction",
          "ruling=contradicted", f"ruling={steering_c.get('ruling', '-')}",
          steering_c.get("ruling") == "contradicted", soft=True)  # model-ruled
    root_c = (inc_c.get("root_cause") or "").lower()
    # "not adopted" must not flag a compliant contradiction statement: the prompt
    # ASKS the model to state what contradicted the correction, so prose like
    # "…PVC metric shows 95% available, contradicting the corrected hypothesis"
    # names the pvc while explicitly refuting it. Only a mention WITHOUT any
    # refuting language counts as adoption.
    refuting = any(t in root_c for t in ("contradict", "ruled out", "not full", "healthy", "95"))
    check("contradicted correction is not adopted", "pvc absent, or mentioned only as refuted",
          f"root_cause={root_c[:60]}", "pvc" not in root_c or refuting,
          soft=True)  # finding prose is LLM-owned; the prompt forbids the carry-over, code can't
    recap(f"{row_c['id'][:8]} · seeded healthy (95% free) — ruling={steering_c.get('ruling', 'absent')}, "
          f"the model concludes from the evidence instead (confidence {inc_c.get('confidence')})")

    # ── step 5d — steering: unverifiable ───────────────────────────────────
    step("5d", "steering — series DELETED: ruling must be UNVERIFIABLE, capped adoption with provenance")
    dim("the series is deleted outright — the correction can no longer be tested at all.")
    dim("expected: unverifiable, the corrected cause adopted only as a leading hypothesis,")
    dim("confidence deterministically capped, and the card saying exactly that.")
    delete_gauge()
    time.sleep(20)
    seed_deleted = mcp.call("prometheus_query", {"expr": DEMO_SERIES}).get("result") or []
    check("deleted series is truly absent from Prometheus", "0 series",
          f"{len(seed_deleted)} series", len(seed_deleted) == 0)
    row_u, last = refire_and_wait(mcp, inc, row_c["id"], seen_ids, webhook_port,
                                  env["ALERTINT_WEBHOOK_TOKEN"], f"demo-unverifiable:{incident_id}", args.triage_timeout)
    if not row_u:
        check("unverifiable-path incident analyzed", "analyzed", last or "none", False)
        return summarize(env)
    seen_ids.add(row_u["id"])  # no phase follows, but keeps the accumulated set consistent
    inc_u = mcp.call("alertint_get_incident", {"incident_id": row_u["id"]})
    steering_u = ((mcp.call("alertint_get_evidence_pack", {"incident_id": row_u["id"]})
                   .get("enrichment") or {}).get("verification") or {}).get("operator_ruling") or {}
    blob("ruling", steering_u)
    check("ruling is unverifiable", "ruling=unverifiable", f"ruling={steering_u.get('ruling', '-')}",
          steering_u.get("ruling") == "unverifiable", soft=True)  # model-ruled
    # hard: with the series deleted the probe can't fetch, backed=false, and the
    # deterministic clamp applies no matter what the model ruled
    check("unverifiable adoption is capped", "confidence <= 0.6",
          f"confidence={inc_u.get('confidence')}", (inc_u.get("confidence") or 1) <= 0.6)
    recap(f"{row_u['id'][:8]} · series deleted — ruling={steering_u.get('ruling', 'absent')}, "
          f"adoption capped (confidence {inc_u.get('confidence')})")

    summarize(env)


def summarize(env):
    # ── audit ───────────────────────────────────────────────────────────────
    step(6, "audit chain (every write-back is hash-chained)")
    mcp = MCPClient(f"http://127.0.0.1:{env.get('ALERTINT_MCP_PORT', '9912')}/mcp", env["ALERTINT_MCP_TOKEN"])
    mcp.initialize()
    res = mcp.call("alertint_verify_audit", {})
    blob("alertint_verify_audit", res)
    check("audit chain intact", "ok=True", f"ok={res.get('ok')} rows={res.get('rows_checked')}",
          res.get("ok") is True)
    dim("same check from the CLI inside the container:")
    subprocess.run(
        ["docker", "exec", "alertint-agent", "/alertint", "verify-audit", "--db", "/data/alertint-agent.db"],
        cwd=REPO, check=False,
    )

    # ── recap: one incident (thread) per phase ──────────────────────────────
    if RECAP:
        print(f"\n{BOLD}━━ what you just saw — one incident per phase, same failure group{RESET}")
        for i, line in enumerate(RECAP, 1):
            info(f"{i}. {line}")
        dim(f"if Slack is wired, these are the {len(RECAP)} threads in your alert channel — ")
        dim("deliberately separate incidents, so each triage ran against a different")
        dim("live-evidence state and you can compare the rulings side by side.")

    # ── summary ─────────────────────────────────────────────────────────────
    passed = sum(1 for c in CHECKS if c[3])
    warned = sum(1 for c in CHECKS if not c[3] and c[4])
    failed = sum(1 for c in CHECKS if not c[3] and not c[4])
    tally = f"{passed}/{len(CHECKS)} checks passed"
    if warned:
        tally += f", {warned} soft warning(s)"
    if failed:
        tally += f", {failed} FAILED"
    print(f"\n{BOLD}━━ summary — {tally}{RESET}")
    for name, expected, actual, ok, soft in CHECKS:
        mark = f"{GREEN}✓{RESET}" if ok else (f"{YELLOW}!{RESET}" if soft else f"{RED}✗{RESET}")
        print(f"   {mark} {name} {DIM}({actual}){RESET}")
    if warned:
        dim("! = soft check on LLM-authored output (ruling strings, finding prose, graded")
        dim("    replays) — a miss is expected model ambiguity, not a broken pipeline")
    print(f"\n{DIM}   stack still running — `task docker:logs` to read it, "
          f"`task docker:down` to stop it.{RESET}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
