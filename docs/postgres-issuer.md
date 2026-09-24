# PostgreSQL password issuer

`postgres-password` is a separate one-use operation grant. It changes the password of one existing application role through one operator-installed function. A later Kubernetes Secret delivery uses a separate grant. WispKey does not create or drop roles, databases, schemas, or functions during an operation.

The operator reviews and installs a `SECURITY DEFINER` function in the exact database named by the target. The following is a template for an existing `appuser` role; replace names only during owner review. Provision the issuer's login password through a protected channel, not a plaintext SQL command or shell history. The function owner must have only the rights needed to alter the fixed application role under the site's PostgreSQL role model. The issuer must be a login role with no elevated flags or role memberships and must have no direct role-management powers. WispKey checks flags and memberships but cannot prove the issuer lacks unrelated object ownership or direct privileges; the database owner must audit those separately.

```sql
-- Run as the trusted function owner on the exact target database.
BEGIN;
CREATE SCHEMA wispkey_admin;
REVOKE ALL ON SCHEMA wispkey_admin FROM PUBLIC;

CREATE FUNCTION wispkey_admin.rotate_app_password(new_password text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF new_password IS NULL OR length(new_password) < 8 THEN
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
COMMIT;
```

Create the `issuer` role separately with `LOGIN`, no `SUPERUSER`, `CREATEROLE`, `CREATEDB`, `REPLICATION`, or `BYPASSRLS`, and no role memberships. The function uses a fixed role name and a quoted password literal; it accepts no caller-selected role, database, or arbitrary SQL. PostgreSQL recommends a trusted `search_path`, `pg_temp` last, and revoking the default `PUBLIC` function execution privilege in the same transaction as creation. [PostgreSQL `CREATE FUNCTION`](https://www.postgresql.org/docs/18/sql-createfunction.html)

Record the function OID and SHA-256 of `pg_get_functiondef` from the target database. The hash is unpadded base64:

```sql
SELECT p.oid AS function_oid,
       rtrim(encode(sha256(convert_to(pg_get_functiondef(p.oid), 'UTF8')),
                    'base64'), '=') AS function_definition_sha256
FROM pg_proc p
WHERE p.oid = 'wispkey_admin.rotate_app_password(text)'::regprocedure;
```

Place these values, the function owner, exact `postgresql://host:port` endpoint, private CA file, fixed database and role names, and separate provider/previous credential IDs in the owner-reviewed catalog. A function replacement, changed owner, changed definition, or CA replacement requires a new catalog snapshot and grant. WispKey checks the function OID, definition hash, owner, signature, ACL, issuer role properties, and database identity before releasing the selected password. This preflight does not prevent a privileged database administrator from changing the function between verification and execution; the destination owner must keep DDL and function ownership under trusted control during rotation.

Use the common version 2 fields from the [runtime guide](operation-runtime.md),
set `kind = "postgres-password"`, and set the common `credential_id` to the
stored new password. Provider and previous-password references must be distinct
credentials in the same project. Add this target block, replacing the illustrative
IDs, OID, endpoint and hash with reviewed values:

```toml
[operation.postgres]
endpoint = "postgresql://database.example:5432"
environment_id = "preview"
environment_owner = "platform"
database = "appdb"
issuer_username = "issuer"
app_username = "appuser"
provider_credential_id = "5af05c13-1c0a-4394-a7a3-7f457ff74a43"
previous_credential_id = "5af05c13-1c0a-4394-a7a3-7f457ff74a44"
ca_file = "/private/database-ca.pem"
function_schema = "wispkey_admin"
function_name = "rotate_app_password"
function_oid = 12345
function_owner = "database_owner"
function_definition_sha256 = "<unpadded base64 SHA-256 from the query above>"
```

The target environment must match the common operation environment. Database,
role, schema and function names use lowercase ASCII SQL identifiers, at most
63 characters, beginning with a letter and containing only letters, digits and
underscores. The catalog contains credential IDs, never their password values.

The endpoint uses a private pinned CA, hostname verification, required TLS, and required SCRAM channel binding. The database must use SCRAM-SHA-256 authentication for issuer and application roles. The operation first authenticates the previous application password, then calls the pinned function with the new password as a bind parameter. It reports verified rotation only after a fresh new-password login succeeds and the previous password is rejected with PostgreSQL SQLSTATE `28P01`. Existing authenticated database sessions continue until they disconnect or are ended separately; consumers must reload the delivered password independently. [PostgreSQL password authentication](https://www.postgresql.org/docs/18/auth-password.html), [PostgreSQL `ALTER ROLE`](https://www.postgresql.org/docs/18/sql-alterrole.html)

Before execution, WispKey requires the issuer session's `log_statement=none`, `log_parameter_max_length=0`, `log_parameter_max_length_on_error=0`, `log_min_duration_statement=-1`, `log_min_duration_sample=-1`, `log_transaction_sample_rate=0`, and `log_duration=off`. Configure these settings as trusted server or role policy; the issuer must not be able to weaken them. PostgreSQL can otherwise log bind values or plaintext `ALTER ROLE` statements. Audit extensions, custom hooks, managed-service logs, and privileged logging changes are outside this check; the destination owner must inspect those facilities and test a synthetic canary before use. The example function replaces errors with a fixed message, but its source and logging behavior still require owner review. [PostgreSQL logging settings](https://www.postgresql.org/docs/18/runtime-config-logging.html), [PostgreSQL `ALTER ROLE` logging caution](https://www.postgresql.org/docs/18/sql-alterrole.html)

The automated synthetic fixture uses a digest-pinned PostgreSQL 18.6 container on loopback, a generated CA, precreated database and roles, and a marked application row. Run `bash tests/support/postgres_operation_fixture.sh` on a Linux CI runner with Docker and Rust. It checks function drift does not release the selected password, verifies the new and old logins, keeps the application row, probes a parameterized failure, and scans container logs for the synthetic password and failure canary. No real database or vault credential is used.
