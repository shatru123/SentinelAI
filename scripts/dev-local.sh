#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_URL="http://localhost:5109/health"
WEB_URL="http://localhost:5056/auth/login"
API_PID=""

cleanup() {
  if [[ -n "${API_PID}" ]] && kill -0 "${API_PID}" 2>/dev/null; then
    echo
    echo "Stopping SentinelAI API..."
    kill "${API_PID}" 2>/dev/null || true
    wait "${API_PID}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

if ! command -v dotnet >/dev/null 2>&1; then
  echo "The .NET 10 SDK is required. Install it before running SentinelAI."
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to check API readiness."
  exit 1
fi

cd "${ROOT_DIR}"

echo "Starting SentinelAI API (InMemory database + in-process job consumer)..."
dotnet run --project src/SentinelAI.Api --launch-profile http &
API_PID=$!

echo "Waiting for API health at ${API_URL}..."
api_ready=false
for attempt in $(seq 1 45); do
  if curl --silent --show-error --fail "${API_URL}" >/dev/null 2>&1; then
    api_ready=true
    break
  fi

  if ! kill -0 "${API_PID}" 2>/dev/null; then
    echo "The API process exited before becoming healthy."
    exit 1
  fi

  sleep 1
done

if [[ "${api_ready}" != "true" ]]; then
  echo "The API did not become healthy within 45 seconds."
  echo "Check the API startup output above."
  exit 1
fi

echo "API is healthy."
echo "Starting SentinelAI Web at http://localhost:5056 ..."
echo "Open ${WEB_URL} once to sign in with the local Development identity."
echo "Press Ctrl+C to stop the Web app and API."
dotnet run --project src/SentinelAI.Web --launch-profile http
