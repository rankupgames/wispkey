#!/usr/bin/env bash
# Disposable, loopback-only PostgreSQL fixture for the ignored issuer test.
set -euo pipefail

name="wkpg-operation-$$-$RANDOM"
scratch="$(mktemp -d)"
created=0
cleanup() {
    if [[ "$created" == 1 ]]; then
        docker rm -f -v "$name" >/dev/null 2>&1 || true
    fi
    if [[ -n "$scratch" && "$scratch" == /tmp/* ]]; then
        rm -rf -- "$scratch"
    fi
}
trap cleanup EXIT

docker run -d --name "$name" -p 127.0.0.1::5432 \
    -e POSTGRES_PASSWORD=synthetic_admin_password_9214 \
    postgres@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722 >/dev/null
created=1
for _ in $(seq 1 60); do
    if docker exec -u postgres "$name" pg_isready -U postgres >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
docker exec -u postgres "$name" pg_isready -U postgres >/dev/null

docker exec -u postgres "$name" openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -days 1 -subj /CN=WispKeySyntheticCA \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout /tmp/wk-ca.key -out /tmp/wk-ca.crt >/dev/null 2>&1
docker exec -u postgres "$name" openssl req -newkey rsa:2048 -sha256 -nodes \
    -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
    -addext extendedKeyUsage=serverAuth \
    -keyout /tmp/wk-server.key -out /tmp/wk-server.csr >/dev/null 2>&1
docker exec -u postgres "$name" openssl x509 -req -in /tmp/wk-server.csr \
    -CA /tmp/wk-ca.crt -CAkey /tmp/wk-ca.key -CAcreateserial \
    -days 1 -sha256 -copy_extensions copy -out /tmp/wk-server.crt >/dev/null 2>&1
docker exec -u postgres "$name" psql -U postgres -v ON_ERROR_STOP=1 \
    -c 'ALTER SYSTEM SET ssl = on' >/dev/null
docker exec -u postgres "$name" psql -U postgres -v ON_ERROR_STOP=1 \
    -c "ALTER SYSTEM SET ssl_cert_file = '/tmp/wk-server.crt'" >/dev/null
docker exec -u postgres "$name" psql -U postgres -v ON_ERROR_STOP=1 \
    -c "ALTER SYSTEM SET ssl_key_file = '/tmp/wk-server.key'" >/dev/null
docker exec -u postgres "$name" psql -U postgres -v ON_ERROR_STOP=1 \
    -c 'ALTER SYSTEM SET log_parameter_max_length = 0' >/dev/null
docker exec -u postgres "$name" psql -U postgres -Atc 'SELECT pg_reload_conf()' >/dev/null
test "$(docker exec -u postgres "$name" psql -U postgres -Atc 'SHOW ssl')" = on

docker exec -i -u postgres "$name" psql -U postgres -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
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

function_identity="$(docker exec -u postgres "$name" psql -U postgres -d appdb -Atc \
    "SELECT p.oid || ',' || rtrim(encode(sha256(convert_to(pg_get_functiondef(p.oid), 'UTF8')), 'base64'), '=') FROM pg_proc p WHERE p.oid = 'wispkey_admin.rotate_app_password(text)'::regprocedure")"
port="$(docker port "$name" 5432/tcp)"
if [[ "$port" != 127.0.0.1:* ]]; then
    echo 'fixture did not bind loopback' >&2
    exit 1
fi
docker cp "$name:/tmp/wk-ca.crt" "$scratch/ca.pem" >/dev/null

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
    cargo test --lib operations::postgres::tests::disposable_postgres_tls_rotation -- --ignored
    test "$(docker exec -u postgres "$name" psql -U postgres -d appdb -Atc 'SELECT marker FROM public.fixture_marker')" = preserved-row
    if docker logs "$name" 2>&1 | grep -Fq 'synthetic_new_password_9214'; then
        echo 'synthetic password appeared in PostgreSQL logs' >&2
        exit 1
    fi
    if docker logs "$name" 2>&1 | grep -Fq 'fail_synthetic_canary_9214'; then
        echo 'synthetic failure canary appeared in PostgreSQL logs' >&2
        exit 1
    fi
fi
