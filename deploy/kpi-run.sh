#!/usr/bin/env bash
set -euo pipefail

N="${1:-200}"
BASE_URL="${BASE_URL:-http://localhost:8080}"
CONTROLPLANE_URL="${CONTROLPLANE_URL:-http://localhost:18080}"
DAY="${DAY:-$(date -u +%F)}"
P="${P:-1}"
RESET="${RESET:-1}"
WAIT="${WAIT:-20}"

cd "$(dirname "$0")"

docker-compose up -d --build >/dev/null

if [ "$RESET" = "1" ]; then
  docker-compose restart controlplane >/dev/null
  sleep 2
fi

baseline_file=$(mktemp)
after_file=$(mktemp)
cleanup() {
  rm -f "$baseline_file" "$after_file"
}
trap cleanup EXIT

curl -s "$CONTROLPLANE_URL/tenants/demo/audit?day=$DAY" >"$baseline_file"

start_ns=$(date +%s%N)
if [ "$P" -gt 1 ]; then
  seq "$N" | xargs -I{} -P "$P" curl -s -o /dev/null "$BASE_URL/checkout" || true
else
  for _ in $(seq 1 "$N"); do
    curl -s -o /dev/null "$BASE_URL/checkout" || true
  done
fi
end_ns=$(date +%s%N)

sleep "$WAIT"

curl -s "$CONTROLPLANE_URL/tenants/demo/audit?day=$DAY" >"$after_file"

python3 - "$N" "$start_ns" "$end_ns" "$baseline_file" "$after_file" <<'PY'
import json
import sys

n = int(sys.argv[1])
start = int(sys.argv[2])
end = int(sys.argv[3])
baseline_path = sys.argv[4]
after_path = sys.argv[5]

def load_counts(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    except FileNotFoundError:
        return {}
    if not raw:
        return {}
    data = json.loads(raw)
    counts = data.get("counts", []) or []
    out = {}
    for c in counts:
        rid = c.get("ruleId")
        if not rid:
            continue
        out[rid] = int(c.get("count", 0))
    return out

before = load_counts(baseline_path)
after = load_counts(after_path)
delta = {rid: max(after.get(rid, 0) - before.get(rid, 0), 0) for rid in set(before) | set(after)}
total = sum(delta.values())
duration_sec = max((end - start) / 1e9, 1e-9)
rps = n / duration_sec
red_per_sec = total / duration_sec
red_per_min = red_per_sec * 60

print(f"requests: {n}")
print(f"duration_sec: {duration_sec:.3f}")
print(f"requests_per_sec: {rps:.2f}")
print(f"redactions_total: {total}")
print(f"redactions_per_sec: {red_per_sec:.2f}")
print(f"redactions_per_min: {red_per_min:.2f}")
print("redactions_by_rule:")
for rid in sorted(delta.keys()):
    print(f"  {rid}: {delta[rid]}")
PY
