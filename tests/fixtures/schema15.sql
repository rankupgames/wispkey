-- Frozen schema 15 DDL from public main 8430305c5f0f03303eb406dde31b54170c1cb32a.
-- Synthetic migration fixture; never construct through the current schema builder.
CREATE TABLE IF NOT EXISTS vault_meta (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS projects (
				id TEXT PRIMARY KEY,
				name TEXT UNIQUE NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS partitions (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				project_id TEXT NOT NULL REFERENCES projects(id),
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				UNIQUE(project_id, name)
				);
				CREATE TABLE IF NOT EXISTS credentials (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL,
					description TEXT NOT NULL DEFAULT '',
					credential_type TEXT NOT NULL,
					encrypted_value TEXT NOT NULL,
				wisp_token TEXT UNIQUE NOT NULL,
				hosts TEXT NOT NULL DEFAULT '',
				tags TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				last_used_at TEXT,
				partition_id TEXT REFERENCES partitions(id),
				origin TEXT NOT NULL DEFAULT '',
				lifecycle_state TEXT NOT NULL DEFAULT 'active',
				review_at TEXT
			);
			CREATE TABLE IF NOT EXISTS audit_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp TEXT NOT NULL,
				event_type TEXT NOT NULL,
				credential_name TEXT,
				wisp_token TEXT,
				target_host TEXT,
				target_path TEXT,
				http_method TEXT,
				response_status INTEGER,
				denied INTEGER NOT NULL DEFAULT 0,
				deny_reason TEXT,
				project_name TEXT
			);

CREATE TABLE IF NOT EXISTS instances (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            secret_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT,
            secret_rotated_at TEXT NOT NULL,
            previous_secret_hash TEXT,
            previous_secret_expires_at TEXT
        );
        CREATE TABLE IF NOT EXISTS instance_scopes (
            id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
            scope_type TEXT NOT NULL,
            scope_value TEXT NOT NULL,
            credential_id TEXT REFERENCES credentials(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            UNIQUE(instance_id, scope_type, scope_value)
        );
        CREATE TABLE IF NOT EXISTS access_requests (
            id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
            credential_name TEXT NOT NULL,
            credential_id TEXT REFERENCES credentials(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'pending',
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            decided_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_instance_scopes_credential_id
            ON instance_scopes(instance_id, credential_id);
        CREATE INDEX IF NOT EXISTS idx_access_requests_credential_id
            ON access_requests(instance_id, credential_id, status);

CREATE TABLE IF NOT EXISTS bootstrap_tokens (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            scope_json TEXT NOT NULL DEFAULT '[]',
            max_uses INTEGER,
            used_count INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        );

CREATE TABLE IF NOT EXISTS browser_fill_requests (
        request_id TEXT PRIMARY KEY,
        name TEXT NOT NULL, project TEXT NOT NULL, origin TEXT NOT NULL,
        requester TEXT NOT NULL, reason TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','completed','failed')),
        expires_at INTEGER NOT NULL, credential_id TEXT NOT NULL, revision TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS operation_grants (
            id TEXT PRIMARY KEY,
            operation TEXT NOT NULL, target TEXT NOT NULL, environment TEXT NOT NULL,
            credential_ref TEXT NOT NULL, project_id TEXT NOT NULL,
            catalog_revision TEXT NOT NULL, credential_revision TEXT NOT NULL,
            provider_credential_ref TEXT, provider_project_id TEXT, provider_revision TEXT,
            old_password_credential_ref TEXT, old_password_revision TEXT,
            requester_instance_id TEXT NOT NULL, instance_generation TEXT NOT NULL,
            session_issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
            max_grant_seconds INTEGER NOT NULL, max_runtime_seconds INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending','started','succeeded','delivery_acknowledged','failed_child','timed_out','canceled','outcome_unknown','revocation_unverified'))
        );
        CREATE TABLE IF NOT EXISTS operation_attempts (
            id TEXT PRIMARY KEY, grant_id TEXT NOT NULL UNIQUE REFERENCES operation_grants(id),
            hard_deadline TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('started','succeeded','delivery_acknowledged','failed_child','timed_out','canceled','outcome_unknown','revocation_unverified')),
            cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
            secret_released INTEGER NOT NULL DEFAULT 0 CHECK(secret_released IN (0,1)),
            provider_released INTEGER NOT NULL DEFAULT 0 CHECK(provider_released IN (0,1)),
            old_password_released INTEGER NOT NULL DEFAULT 0 CHECK(old_password_released IN (0,1)),
            exit_code INTEGER, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS operation_audit (
            timestamp TEXT NOT NULL, requester TEXT NOT NULL, operation TEXT NOT NULL,
            target TEXT NOT NULL, environment TEXT NOT NULL,
            credential_ref TEXT, expires_at TEXT NOT NULL,
            result TEXT NOT NULL CHECK(result IN ('authorized','denied_identity','denied','started','succeeded','delivery_acknowledged','failed_child','timed_out','cancel_requested','canceled','outcome_unknown','revocation_unverified'))
        );
        CREATE INDEX IF NOT EXISTS operation_attempts_state ON operation_attempts(state);

CREATE TABLE IF NOT EXISTS auth_registry (
            credential_id TEXT PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
            auth_id TEXT UNIQUE NOT NULL,
            metadata_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_bundles (
            partition_id TEXT NOT NULL REFERENCES partitions(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            bundle_json TEXT NOT NULL,
            PRIMARY KEY(partition_id, name)
        );

CREATE TABLE IF NOT EXISTS signup_profiles (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, revision TEXT NOT NULL,
        partition_id TEXT NOT NULL REFERENCES partitions(id), encrypted_value TEXT NOT NULL,
        UNIQUE(partition_id,name));
