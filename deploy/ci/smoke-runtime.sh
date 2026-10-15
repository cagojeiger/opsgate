#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ] || [[ "$1" == -* ]]; then
  echo "usage: $0 IMAGE (loaded native image, or remote child manifest @sha256:DIGEST)" >&2
  exit 1
fi
runtime_image="$1"
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) runtime_arch=amd64 ;;
  Linux/aarch64|Linux/arm64) runtime_arch=arm64 ;;
  *) echo 'runtime smoke requires a native Linux amd64/arm64 runner' >&2; exit 1 ;;
esac

report_dir="$(pwd)/reports"
mkdir -p "$report_dir"
scratch="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/opsgate-runtime-smoke.XXXXXX")"
smoke_name="$(basename "$scratch")"
network_id=''
postgres_id=''
app_id=''
cleanup() {
  result=$?
  trap - EXIT INT TERM
  if [ "$result" -ne 0 ]; then
    if [ -n "$app_id" ]; then
      docker logs "$app_id" > "$report_dir/smoke-runtime-app.log" 2>&1 || true
    fi
    if [ -n "$postgres_id" ]; then
      docker logs "$postgres_id" > "$report_dir/smoke-runtime-postgres.log" 2>&1 || true
    fi
  fi
  if [ -n "$app_id" ]; then docker rm -f -v "$app_id" >/dev/null 2>&1 || true; fi
  if [ -n "$postgres_id" ]; then docker rm -f -v "$postgres_id" >/dev/null 2>&1 || true; fi
  if [ -n "$network_id" ]; then docker network rm "$network_id" >/dev/null 2>&1 || true; fi
  rm -rf -- "$scratch"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$runtime_image" =~ @sha256:[0-9a-f]{64}$ ]]; then
  docker pull --quiet "$runtime_image" >/dev/null
fi
# PR builds load a local tag; releases pull an immutable executable manifest.
# Resolve either input once and execute its fixed local image ID.
docker image inspect "$runtime_image" > "$scratch/image.json"
python3 - "$scratch/image.json" "$runtime_arch" <<'PY'
import json, sys
image = json.load(open(sys.argv[1]))[0]
assert image['Os'] == 'linux' and image['Architecture'] == sys.argv[2]
assert image['Config']['User'] == '10001:10001'
assert image['Config']['WorkingDir'] == '/app'
assert image['Config']['Entrypoint'] == ['/usr/local/bin/opsgate-api']
assert '9091/tcp' in image['Config']['ExposedPorts']
PY
runtime_image_id="$(python3 - "$scratch/image.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))[0]['Id'])
PY
)"

network_id="$(docker network create "$smoke_name")"
# Disposable CI fixture credentials, never a production database or secret.
postgres_id="$(docker run --detach --name "$smoke_name-postgres" \
  --network "$network_id" --network-alias postgres \
  --env POSTGRES_USER=appuser --env POSTGRES_PASSWORD=runtime-smoke-only \
  --env POSTGRES_DB=opsgate_smoke postgres:17)"
postgres_ready=false
for _ in $(seq 1 60); do
  if docker exec "$postgres_id" pg_isready -h 127.0.0.1 -p 5432 -U appuser -d opsgate_smoke >/dev/null 2>&1; then
    postgres_ready=true
    break
  fi
  sleep 1
done
[ "$postgres_ready" = true ] || { echo 'Postgres fixture did not become ready' >&2; exit 1; }
postgres_version="$(docker exec "$postgres_id" psql -U appuser -d opsgate_smoke -Atc 'SHOW server_version_num;')"
[[ "$postgres_version" =~ ^17[0-9]{4}$ ]] || { echo 'Postgres fixture must use version 17' >&2; exit 1; }

mkdir -p "$scratch/config"
# Supplying master_key only through this mounted file also verifies /app/config
# lookup from the preserved WORKDIR. The all-zero key is a public test fixture.
cat > "$scratch/config/local.toml" <<'TOML'
master_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
[signup]
allowed_email_patterns = []
TOML
chmod 755 "$scratch" "$scratch/config"
chmod 644 "$scratch/config/local.toml"
# Empty username deliberately exercises SQLx's whoami -> passwd appuser path.
fixture_dsn='postgresql://:runtime-smoke-only@postgres:5432/opsgate_smoke?sslmode=disable'
app_id="$(docker create --name "$smoke_name-app" --network "$network_id" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --publish 127.0.0.1::9091 \
  --mount "type=bind,src=$scratch/config,dst=/app/config,readonly" \
  --env OPSGATE_DATABASE_URL="$fixture_dsn" \
  --env OPSGATE_DATABASE_MIGRATE_URL="$fixture_dsn" \
  --env OPSGATE_AUTHGATE_URL=https://auth.example.test \
  --env OPSGATE_PUBLIC_URL=http://localhost:9091 \
  --env OPSGATE_OAUTH_CLIENT_ID=runtime-smoke \
  --env OPSGATE_OAUTH_REDIRECT_URL=http://localhost:9091/callback \
  --env OPSGATE_RESOURCE_URL=http://localhost:9091/mcp \
  --env LOG_FORMAT=json --env RUST_LOG=opsgate_api=info \
  "$runtime_image_id")"
docker cp "$app_id:/etc/passwd" "$scratch/passwd"
docker cp "$app_id:/etc/group" "$scratch/group"
docker cp "$app_id:/etc/ssl/certs/ca-certificates.crt" "$scratch/ca-certificates.crt"
python3 - "$scratch" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
passwd = [line.split(':') for line in (root / 'passwd').read_text().splitlines()]
group = [line.split(':') for line in (root / 'group').read_text().splitlines()]
assert [row for row in passwd if row[0] == 'appuser' or row[2] == '10001'] == [
    ['appuser', 'x', '10001', '10001', '', '/nonexistent', '/usr/sbin/nologin']]
assert [row for row in group if row[0] == 'app' or row[2] == '10001'] == [
    ['app', 'x', '10001', '']]
assert '-----BEGIN CERTIFICATE-----' in (root / 'ca-certificates.crt').read_text()
PY
docker start "$app_id" >/dev/null
app_port="$(docker port "$app_id" 9091/tcp)"
[[ "$app_port" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || { echo 'unexpected smoke port mapping' >&2; exit 1; }
http_base="http://127.0.0.1:${BASH_REMATCH[1]}"
app_ready=false
for _ in $(seq 1 60); do
  if [ "$(docker inspect --format '{{.State.Running}}' "$app_id")" != true ]; then
    echo 'runtime exited before HTTP readiness' >&2
    exit 1
  fi
  health="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 "$http_base/health" || true)"
  ready="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 "$http_base/ready" || true)"
  if [ "$health" = 200 ] && [ "$ready" = 200 ]; then
    app_ready=true
    break
  fi
  sleep 1
done
[ "$app_ready" = true ] || { echo 'runtime HTTP probes did not become ready' >&2; exit 1; }
docker top "$app_id" -eo uid,gid > "$scratch/process-identity.txt"
database_user="$(docker exec "$postgres_id" psql -U appuser -d opsgate_smoke -Atc \
  "SELECT DISTINCT usename FROM pg_stat_activity WHERE datname = 'opsgate_smoke' AND client_addr IS NOT NULL AND pid <> pg_backend_pid();")"
[ "$database_user" = appuser ] || { echo 'username-omitted DSN did not connect as appuser' >&2; exit 1; }
docker stop --time 15 "$app_id" >/dev/null
docker inspect "$app_id" > "$scratch/container.json"
python3 - "$scratch" "$runtime_image" "$runtime_arch" "$postgres_version" "$report_dir/smoke-runtime.json" <<'PY'
from pathlib import Path
import json, sys
root, image, arch, postgres, report = sys.argv[1:]
root = Path(root)
container = json.loads((root / 'container.json').read_text())[0]
image_id = json.loads((root / 'image.json').read_text())[0]['Id']
assert container['Image'] == image_id
assert container['State']['Running'] is False
assert container['State']['ExitCode'] == 0 and container['State']['OOMKilled'] is False
assert container['HostConfig']['ReadonlyRootfs'] is True
assert any(mount['Destination'] == '/app/config' and mount['RW'] is False
           for mount in container['Mounts'])
processes = [line.split() for line in (root / 'process-identity.txt').read_text().splitlines()[1:]]
assert processes and all(row == ['10001', '10001'] for row in processes)
Path(report).write_text(json.dumps({
    'image': image, 'image_id': image_id, 'platform': 'linux/' + arch,
    'uid': 10001, 'gid': 10001,
    'username': 'appuser', 'group': 'app', 'workdir': '/app',
    'readonly_rootfs': True, 'readonly_config_mount': True,
    'ca_bundle': '/etc/ssl/certs/ca-certificates.crt',
    'postgres_server_version_num': int(postgres), 'dsn_username_omitted': True,
    'database_user': 'appuser', 'health_status': 200, 'ready_status': 200,
    'sigterm_exit_code': 0,
}, indent=2) + '\n')
PY
echo "Runtime smoke passed: linux/$runtime_arch, appuser 10001:10001, read-only rootfs, PostgreSQL 17, HTTP probes, SIGTERM exit 0"
