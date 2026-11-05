#!/usr/bin/env bash
# Disposable, loopback-only PostgreSQL fixture for the ignored issuer test.
# WISPKEY_CONTAINER_ENGINE selects a Docker-compatible CLI (default: docker).
# WISPKEY_FIXTURE_CONTAINER_NAME selects an exact container name for CI cleanup
# checks. The run fails without removal when that name already exists.
set -euo pipefail

engine="${WISPKEY_CONTAINER_ENGINE:-docker}"
name="${WISPKEY_FIXTURE_CONTAINER_NAME:-wkpg-operation-$$-$RANDOM}"
if [[ ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]]; then
    echo 'invalid fixture container name' >&2
    exit 2
fi
# Budgeted CI requires engine-created containers in its slice.
placement=()
if [[ -n "${CI_BUDGET_CGROUP+set}" ]]; then
    if [[ ! "$CI_BUDGET_CGROUP" =~ ^/[A-Za-z0-9_.-]+\.slice$ ]]; then
        echo 'CI_BUDGET_CGROUP must name a systemd slice' >&2
        exit 2
    fi
    placement=(--cgroup-parent "${CI_BUDGET_CGROUP#/}")
fi
scratch="$(mktemp -d)"
cleanup() {
    local status=$? container
    if [[ -f "$scratch/container.cid" ]]; then
        container="$(cat "$scratch/container.cid")"
        if [[ ! "$container" =~ ^[a-f0-9]{64}$ ]] || ! "$engine" rm -f -v "$container" >/dev/null 2>&1; then
            echo "PostgreSQL fixture cleanup failed; owned resource evidence remains in $scratch" >&2
            if [[ "$status" == 0 ]]; then status=1; fi
            exit "$status"
        fi
    fi
    # mktemp created this exact directory, including when TMPDIR is customized.
    rm -rf -- "$scratch"
    exit "$status"
}
trap cleanup EXIT

"$engine" create --cidfile "$scratch/container.cid" --name "$name" ${placement[@]+"${placement[@]}"} -p 127.0.0.1::5432 \
    -e POSTGRES_PASSWORD=synthetic_admin_password_9214 \
    -e POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 \
    docker.io/library/postgres@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722 >/dev/null
container="$(cat "$scratch/container.cid")"
if [[ ! "$container" =~ ^[a-f0-9]{64}$ ]]; then
    echo 'fixture container ID is invalid' >&2
    exit 1
fi
"$engine" start "$container" >/dev/null
# Use the recorded ID for all later commands, including cleanup.
name="$container"
for _ in $(seq 1 60); do
    if "$engine" exec -u postgres "$name" pg_isready -U postgres >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
"$engine" exec -u postgres "$name" pg_isready -U postgres >/dev/null

"$engine" exec -u postgres "$name" openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -days 1 -subj /CN=WispKeySyntheticCA \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout /tmp/wk-ca.key -out /tmp/wk-ca.crt >/dev/null 2>&1
"$engine" exec -u postgres "$name" openssl req -newkey rsa:2048 -sha256 -nodes \
    -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
    -addext extendedKeyUsage=serverAuth \
    -keyout /tmp/wk-server.key -out /tmp/wk-server.csr >/dev/null 2>&1
"$engine" exec -u postgres "$name" openssl x509 -req -in /tmp/wk-server.csr \
    -CA /tmp/wk-ca.crt -CAkey /tmp/wk-ca.key -CAcreateserial \
    -days 1 -sha256 -copy_extensions copy -out /tmp/wk-server.crt >/dev/null 2>&1
"$engine" exec -u postgres "$name" psql -U postgres -v ON_ERROR_STOP=1 \
    -c 'ALTER SYSTEM SET ssl = on' >/dev/null
"$engine" exec -u postgres "$name" psql -U postgres -v ON_ERROR_STOP=1 \
    -c "ALTER SYSTEM SET ssl_cert_file = '/tmp/wk-server.crt'" >/dev/null
"$engine" exec -u postgres "$name" psql -U postgres -v ON_ERROR_STOP=1 \
    -c "ALTER SYSTEM SET ssl_key_file = '/tmp/wk-server.key'" >/dev/null
"$engine" exec -u postgres "$name" psql -U postgres -v ON_ERROR_STOP=1 \
    -c 'ALTER SYSTEM SET log_parameter_max_length = 0' >/dev/null
"$engine" exec -u postgres "$name" psql -U postgres -Atc 'SELECT pg_reload_conf()' >/dev/null
test "$("$engine" exec -u postgres "$name" psql -U postgres -Atc 'SHOW ssl')" = on

"$engine" exec -i -u postgres "$name" psql -U postgres -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE ROLE issuer LOGIN PASSWORD 'synthetic_issuer_password_9214';
CREATE ROLE appuser LOGIN PASSWORD 'synthetic_old_password_9214';
CREATE DATABASE appdb;
\connect appdb
BEGIN;
CREATE SCHEMA wispkey_admin;
CREATE FUNCTION wispkey_admin.rotate_app_password(new_password text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF new_password IS NULL OR length(new_password) < 8 OR new_password LIKE 'fail_%' THEN
        RAISE EXCEPTION 'rotation failed';
    END IF;
    EXECUTE format('ALTER ROLE %I PASSWORD %L', 'appuser', new_password);
EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'rotation failed';
END;
$$;
REVOKE ALL ON FUNCTION wispkey_admin.rotate_app_password(text) FROM PUBLIC;
GRANT USAGE ON SCHEMA wispkey_admin TO issuer;
GRANT EXECUTE ON FUNCTION wispkey_admin.rotate_app_password(text) TO issuer;
CREATE TABLE public.fixture_marker (marker text NOT NULL);
INSERT INTO public.fixture_marker VALUES ('preserved-row');
GRANT SELECT ON public.fixture_marker TO appuser;
COMMIT;
SQL

function_identity="$("$engine" exec -u postgres "$name" psql -U postgres -d appdb -Atc \
    "SELECT p.oid || ',' || rtrim(encode(sha256(convert_to(pg_get_functiondef(p.oid), 'UTF8')), 'base64'), '=') FROM pg_proc p WHERE p.oid = 'wispkey_admin.rotate_app_password(text)'::regprocedure")"
port="$("$engine" port "$name" 5432/tcp)"
if [[ "$port" != 127.0.0.1:* ]]; then
    echo 'fixture did not bind loopback' >&2
    exit 1
fi
"$engine" cp "$name:/tmp/wk-ca.crt" "$scratch/ca.pem" >/dev/null

if [[ "${1:-}" == --hold ]]; then
    # Windows Cargo can run against the WSL Docker daemon while this waits.
    external_ca="${2:?provide an absolute scratch CA path}"
    cp "$scratch/ca.pem" "$external_ca"
    echo "ENDPOINT=postgresql://$port"
    echo "CA=$external_ca"
    echo "OID=${function_identity%%,*}"
    echo "HASH=${function_identity#*,}"
    echo READY
    read -r -p 'Press Enter after the focused test to remove the fixture: ' _
else
    export WISPKEY_TEST_PG_FIXTURE_MARKER=wispkey-synthetic-postgres-v1
    export WISPKEY_TEST_PG_ENDPOINT="postgresql://$port"
    export WISPKEY_TEST_PG_CA="$scratch/ca.pem"
    export WISPKEY_TEST_PG_FUNCTION_OID="${function_identity%%,*}"
    export WISPKEY_TEST_PG_FUNCTION_HASH="${function_identity#*,}"
    cargo test --locked --lib operations::postgres::tests::disposable_postgres_tls_rotation -- --ignored --exact
    # Authenticate over TCP with the new password, so a zero-test Cargo run cannot pass.
    test "$("$engine" exec -e PGPASSWORD=synthetic_new_password_9214 -e PGSSLMODE=require "$name" \
        psql -w -h 127.0.0.1 -U appuser -d appdb -Atc 'SELECT marker FROM public.fixture_marker')" = preserved-row
    "$engine" logs "$name" >"$scratch/postgres.log" 2>&1
    if grep -Fq 'synthetic_new_password_9214' "$scratch/postgres.log"; then
        echo 'synthetic password appeared in PostgreSQL logs' >&2
        exit 1
    fi
    if grep -Fq 'fail_synthetic_canary_9214' "$scratch/postgres.log"; then
        echo 'synthetic failure canary appeared in PostgreSQL logs' >&2
        exit 1
    fi
fi
