#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
REPO_DIR=$(cd "${SCRIPT_DIR}/../.." && pwd)
# shellcheck source=integration/common.sh
source "${SCRIPT_DIR}/../common.sh"

PGDOG_PORT="${PGDOG_OAUTH_PORT:-7643}"
IDP_PORT="${PGDOG_OAUTH_IDP_PORT:-9443}"
JWKS_PORT="${PGDOG_OAUTH_JWKS_PORT:-9444}"
ISSUER="https://localhost:${IDP_PORT}/issuer"
JWKS_ORIGIN="https://localhost:${JWKS_PORT}"
SCOPE="openid db.connect"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pgdog-oauth.XXXXXX")
CLIENT="${WORK_DIR}/oauth_client"
CA="${WORK_DIR}/ca.crt"
SERVER_CERT="${WORK_DIR}/server.crt"
SERVER_KEY="${WORK_DIR}/server.key"
SECRET_FILE="${WORK_DIR}/client.secret"
PROVIDER_LOG="${WORK_DIR}/provider.log"
PGDOG_LOG="${WORK_DIR}/pgdog.log"
IDP_PID=""
export PGDOG_STOP_TRAP=1

capture_pgdog_log() {
    if [[ -f "${REPO_DIR}/integration/log.txt" ]]; then
        cat "${REPO_DIR}/integration/log.txt" >> "${PGDOG_LOG}"
    fi
}

cleanup() {
    capture_pgdog_log
    stop_pgdog >/dev/null 2>&1 || true
    if [[ -n "${IDP_PID}" ]]; then
        kill "${IDP_PID}" >/dev/null 2>&1 || true
        wait "${IDP_PID}" >/dev/null 2>&1 || true
    fi
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

for command in psql pg_config cc python3 openssl curl; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "${command} is required for the OAuth integration suite" >&2
        exit 1
    fi
done
if ! pg_config --version | grep -Eq '^PostgreSQL 18\.'; then
    echo "PostgreSQL 18 libpq headers are required, found: $(pg_config --version)" >&2
    exit 1
fi

cc -std=c11 -Wall -Wextra -Werror \
    -I"$(pg_config --includedir)" \
    "${SCRIPT_DIR}/oauth_client.c" \
    -L"$(pg_config --libdir)" \
    -Wl,-rpath,"$(pg_config --libdir)" \
    -lpq \
    -o "${CLIENT}"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
    -subj '/CN=PgDog OAuth Test CA' \
    -keyout "${WORK_DIR}/ca.key" -out "${CA}" >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes \
    -subj '/CN=localhost' \
    -keyout "${SERVER_KEY}" -out "${WORK_DIR}/server.csr" >/dev/null 2>&1
cat > "${WORK_DIR}/server.ext" <<'EOF'
subjectAltName=DNS:localhost
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -sha256 -days 2 \
    -in "${WORK_DIR}/server.csr" \
    -CA "${CA}" -CAkey "${WORK_DIR}/ca.key" -CAcreateserial \
    -extfile "${WORK_DIR}/server.ext" \
    -out "${SERVER_CERT}" >/dev/null 2>&1
chmod 600 "${WORK_DIR}/ca.key" "${SERVER_KEY}"
printf '%s\n' 'super-secret-value' > "${SECRET_FILE}"
chmod 600 "${SECRET_FILE}"

python3 "${SCRIPT_DIR}/mock_idp.py" \
    --port "${IDP_PORT}" \
    --jwks-port "${JWKS_PORT}" \
    --cert "${SERVER_CERT}" \
    --key "${SERVER_KEY}" \
    --secret 'super-secret-value' \
    --log "${PROVIDER_LOG}" &
IDP_PID=$!

for _ in $(seq 1 100); do
    if curl --silent --fail --cacert "${CA}" "https://localhost:${IDP_PORT}/health" >/dev/null; then
        break
    fi
    if ! kill -0 "${IDP_PID}" >/dev/null 2>&1; then
        echo "OAuth mock provider exited during startup" >&2
        exit 1
    fi
    sleep 0.1
done
curl --silent --fail --cacert "${CA}" "https://localhost:${IDP_PORT}/health" >/dev/null

write_config() {
    local directory=$1
    local mode=$2
    local max_requests=${3:-16}
    local jwks_override=${4:-}
    mkdir -p "${directory}"
    sed \
        -e "s|__TLS_CERTIFICATE__|${SERVER_CERT}|" \
        -e "s|__TLS_PRIVATE_KEY__|${SERVER_KEY}|" \
        -e "s|port = 7643|port = ${PGDOG_PORT}|" \
        "${SCRIPT_DIR}/pgdog.toml" > "${directory}/pgdog.toml"
    cp "${SCRIPT_DIR}/users.toml" "${directory}/users.toml"
    cat >> "${directory}/pgdog.toml" <<EOF

[oauth]
mode = "${mode}"
issuer = "${ISSUER}"
audience = "postgres"
scopes = ["openid", "db.connect"]
http_timeout = 1000
clock_skew = 1000
ca_certificate = "${CA}"
max_concurrent_requests = ${max_requests}
EOF
    if [[ "${mode}" == "jwt" ]]; then
        cat >> "${directory}/pgdog.toml" <<EOF
algorithms = ["RS256"]
jwks_cache_ttl = 5000
EOF
        if [[ -n "${jwks_override}" ]]; then
            printf 'jwks_uri = "%s"\n' "${jwks_override}" >> "${directory}/pgdog.toml"
        fi
    else
        cat >> "${directory}/pgdog.toml" <<EOF
client_id = "pgdog"
client_secret_file = "${SECRET_FILE}"
EOF
    fi
}

stop_and_capture() {
    capture_pgdog_log
    stop_pgdog >/dev/null 2>&1 || true
}

start_pgdog() {
    local directory=$1
    stop_and_capture
    run_pgdog "${directory}"
    local pid
    pid=$(cat "${REPO_DIR}/integration/pgdog.pid")
    for _ in $(seq 1 100); do
        if (exec 3<>"/dev/tcp/127.0.0.1/${PGDOG_PORT}") 2>/dev/null; then
            exec 3>&- 3<&-
            return
        fi
        if ! kill -0 "${pid}" >/dev/null 2>&1; then
            echo "PgDog exited during OAuth suite startup" >&2
            capture_pgdog_log
            exit 1
        fi
        sleep 0.1
    done
    echo "PgDog did not open port ${PGDOG_PORT}" >&2
    exit 1
}

token() {
    curl --silent --show-error --fail --cacert "${CA}" \
        "https://localhost:${IDP_PORT}/token/$1"
}

control() {
    curl --silent --show-error --fail --cacert "${CA}" -X POST \
        "https://localhost:${IDP_PORT}$1" >/dev/null
}

conninfo() {
    local host=${1:-localhost}
    local root=${2:-${CA}}
    local sslmode=${3:-verify-full}
    printf "host=%s port=%s dbname=pgdog user=oauth_user sslmode=%s sslrootcert=%s gssencmode=disable connect_timeout=5 oauth_issuer=%s oauth_client_id=pgdog oauth_scope='%s'" \
        "${host}" "${PGDOG_PORT}" "${sslmode}" "${root}" "${ISSUER}" "${SCOPE}"
}

run_client() {
    local bearer=$1
    local mode=$2
    local connection=${3:-$(conninfo)}
    local marker=${4:--}
    "${CLIENT}" "${connection}" "${bearer}" "${mode}" \
        "${ISSUER}/.well-known/openid-configuration" "${SCOPE}" "${marker}"
}

control '/control/cross-origin?enabled=0'
JWT_CONFIG="${WORK_DIR}/jwt"
write_config "${JWT_CONFIG}" jwt 16
start_pgdog "${JWT_CONFIG}"

GOOD_TOKEN=$(token good)
run_client "${GOOD_TOKEN}" success
for kind in expired bad-signature wrong-user wrong-audience missing-scope wrong-typ; do
    run_client "$(token "${kind}")" auth-failure
 done

MARKER="${WORK_DIR}/hook-called"
rm -f "${MARKER}"
run_client "${GOOD_TOKEN}" preauth-failure "$(conninfo localhost "${CA}" disable)" "${MARKER}"
[[ ! -e "${MARKER}" ]]
rm -f "${MARKER}"
run_client "${GOOD_TOKEN}" preauth-failure "$(conninfo localhost "${SCRIPT_DIR}/../tls/ca.crt")" "${MARKER}"
[[ ! -e "${MARKER}" ]]
rm -f "${MARKER}"
run_client "${GOOD_TOKEN}" preauth-failure "$(conninfo 127.0.0.1 "${CA}")" "${MARKER}"
[[ ! -e "${MARKER}" ]]

ROTATED_TOKEN=$(token rotated)
control '/control/rotate'
run_client "${ROTATED_TOKEN}" success
run_client "$(token unknown)" auth-failure

control '/control/cross-origin?enabled=1'
JWT_CROSS_CONFIG="${WORK_DIR}/jwt-cross"
write_config "${JWT_CROSS_CONFIG}" jwt 16
start_pgdog "${JWT_CROSS_CONFIG}"
run_client "$(token good)" auth-failure

JWT_OVERRIDE_CONFIG="${WORK_DIR}/jwt-override"
write_config "${JWT_OVERRIDE_CONFIG}" jwt 16 "${JWKS_ORIGIN}/jwks"
start_pgdog "${JWT_OVERRIDE_CONFIG}"
run_client "$(token good)" success
control '/control/cross-origin?enabled=0'

INTROSPECTION_CONFIG="${WORK_DIR}/introspection"
write_config "${INTROSPECTION_CONFIG}" introspection 2
start_pgdog "${INTROSPECTION_CONFIG}"
run_client opaque-good success
for bearer in opaque-inactive opaque-error opaque-wrong-user opaque-wrong-audience opaque-missing-scope; do
    run_client "${bearer}" auth-failure
done

BEFORE_INTROSPECTION=$(curl --silent --fail --cacert "${CA}" "https://localhost:${IDP_PORT}/stats" | python3 -c 'import json,sys; print(json.load(sys.stdin)["introspection"])')
RESULTS="${WORK_DIR}/concurrency-results"
: > "${RESULTS}"
CLIENT_PIDS=()
for _ in $(seq 1 6); do
    (
        if run_client opaque-slow success >/dev/null 2>&1; then
            echo success >> "${RESULTS}"
        else
            echo rejected >> "${RESULTS}"
        fi
    ) &
    CLIENT_PIDS+=("$!")
done
for pid in "${CLIENT_PIDS[@]}"; do
    wait "${pid}"
done
AFTER_STATS=$(curl --silent --fail --cacert "${CA}" "https://localhost:${IDP_PORT}/stats")
AFTER_INTROSPECTION=$(printf '%s' "${AFTER_STATS}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["introspection"])')
MAX_ACTIVE=$(printf '%s' "${AFTER_STATS}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["max_active_introspection"])')
REJECTED=$(grep -c '^rejected$' "${RESULTS}" || true)
if (( REJECTED < 1 || MAX_ACTIVE > 2 || AFTER_INTROSPECTION - BEFORE_INTROSPECTION > 2 )); then
    echo "OAuth concurrency bound failed: rejected=${REJECTED} max_active=${MAX_ACTIVE} provider_delta=$((AFTER_INTROSPECTION - BEFORE_INTROSPECTION))" >&2
    exit 1
fi

BEFORE_OVERSIZE=${AFTER_INTROSPECTION}
OVERSIZED_TOKEN=$(python3 -c 'print("a" * 65537)')
run_client "${OVERSIZED_TOKEN}" auth-failure
AFTER_OVERSIZE=$(curl --silent --fail --cacert "${CA}" "https://localhost:${IDP_PORT}/stats" | python3 -c 'import json,sys; print(json.load(sys.stdin)["introspection"])')
if [[ "${BEFORE_OVERSIZE}" != "${AFTER_OVERSIZE}" ]]; then
    echo "oversized bearer token reached the introspection endpoint" >&2
    exit 1
fi
run_client opaque-timeout auth-failure

capture_pgdog_log
for secret in "${GOOD_TOKEN}" "${ROTATED_TOKEN}" opaque-good super-secret-value; do
    if grep -F -- "${secret}" "${PGDOG_LOG}" "${PROVIDER_LOG}" >/dev/null; then
        echo "OAuth credential leaked into logs" >&2
        exit 1
    fi
done

echo "PASS: PostgreSQL 18 libpq OAuth JWT and introspection interoperability"
