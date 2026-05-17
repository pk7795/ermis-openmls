//! Crypto provider for MLS operations
//!
//! Provides a persistent MLS provider backed by SQLite (via `rusqlite`),
//! replacing the default in-memory storage so that MLS state survives
//! app restarts on mobile.

use std::sync::Mutex;

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::OptionalExtension;
use serde::Serialize;

// ============================================================================
// JSON Codec for SqliteStorageProvider
// ============================================================================

/// A simple JSON codec that satisfies `openmls_sqlite_storage::Codec`.
#[derive(Default)]
pub struct JsonCodec;

impl openmls_sqlite_storage::Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

// ============================================================================
// PersistentCryptoProvider — RustCrypto + SqliteStorageProvider
// ============================================================================

/// Persistent MLS crypto provider.
/// Implements [`OpenMlsProvider`] by delegating crypto/rand to [`RustCrypto`]
/// and storage to [`SqliteStorageProvider`].
pub struct PersistentCryptoProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
    db_path: String,
}

impl PersistentCryptoProvider {
    /// Open (or create) a SQLite database at the given path and run migrations.
    pub fn new_with_path(db_path: &str) -> Result<Self, String> {
        let connection =
            Connection::open(db_path).map_err(|e| format!("Failed to open DB: {e}"))?;
        let mut storage = SqliteStorageProvider::new(connection);
        storage
            .run_migrations()
            .map_err(|e| format!("Failed to run migrations: {e}"))?;

        // Create custom identity table (not part of upstream migrations)
        Self::create_identity_table(db_path)?;

        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
            db_path: db_path.to_string(),
        })
    }

    /// Create an in-memory SQLite provider (useful for tests).
    pub fn new_in_memory() -> Result<Self, String> {
        Self::new_with_path(":memory:")
    }

    /// Create the custom identity table for storing user identity data.
    fn create_identity_table(db_path: &str) -> Result<(), String> {
        let conn = Connection::open(db_path).map_err(|e| format!("Failed to open DB: {e}"))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS openmls_uniffi_identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                user_id TEXT NOT NULL,
                identity_bytes BLOB NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("Failed to create identity table: {e}"))?;
        Ok(())
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    fn read_conn(&self) -> Result<Connection, String> {
        Connection::open_with_flags(&self.db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| format!("DB open error: {e}"))
    }

    fn write_conn(&self) -> Result<Connection, String> {
        Connection::open(&self.db_path).map_err(|e| format!("DB open error: {e}"))
    }

    /// Decode a group_id blob (JSON-encoded GroupId) into a CID string.
    fn decode_group_id_blob(blob: &[u8]) -> String {
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(blob) {
            if let Some(vec_val) = parsed
                .get("value")
                .and_then(|v| v.get("vec"))
                .and_then(|v| v.as_array())
            {
                let bytes: Vec<u8> = vec_val
                    .iter()
                    .filter_map(|b| b.as_u64().map(|n| n as u8))
                    .collect();
                return String::from_utf8_lossy(&bytes).to_string();
            }
        }
        String::from_utf8_lossy(blob).to_string()
    }

    /// Encode a CID string as a GroupId JSON blob for SQL queries.
    fn encode_cid_as_blob(cid: &str) -> Vec<u8> {
        let bytes: Vec<u8> = cid.bytes().collect();
        serde_json::to_vec(&serde_json::json!({"value": {"vec": bytes}}))
            .unwrap_or_else(|_| cid.as_bytes().to_vec())
    }

    // ========================================================================
    // Group Queries & Management
    // ========================================================================

    /// Query stored group IDs (CIDs) from the database.
    pub fn stored_group_ids(&self) -> Result<Vec<String>, String> {
        let conn = self.read_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT group_id FROM openmls_group_data WHERE data_type = 'group_state'",
            )
            .map_err(|e| format!("Query error: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                let blob: Vec<u8> = row.get(0)?;
                Ok(Self::decode_group_id_blob(&blob))
            })
            .map_err(|e| format!("Query error: {e}"))?;

        let mut ids = Vec::new();
        for row in rows {
            ids.push(row.map_err(|e| format!("Row error: {e}"))?);
        }
        Ok(ids)
    }

    /// Count the number of groups stored in the database.
    pub fn group_count(&self) -> Result<u32, String> {
        let conn = self.read_conn()?;
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(DISTINCT group_id) FROM openmls_group_data WHERE data_type = 'group_state'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("Query error: {e}"))?;
        Ok(count)
    }

    /// Delete all data for a specific group by CID.
    pub fn delete_group(&self, cid: &str) -> Result<(), String> {
        let conn = self.write_conn()?;
        let blob = Self::encode_cid_as_blob(cid);

        for table in &[
            "openmls_group_data",
            "openmls_proposals",
            "openmls_own_leaf_nodes",
            "openmls_epoch_keys_pairs",
        ] {
            conn.execute(
                &format!("DELETE FROM {} WHERE group_id = ?1", table),
                rusqlite::params![blob],
            )
            .map_err(|e| format!("Delete error in {}: {e}", table))?;
        }
        Ok(())
    }

    /// Delete all group data from the database (useful for logout/reset).
    pub fn delete_all_groups(&self) -> Result<(), String> {
        let conn = self.write_conn()?;
        for table in &[
            "openmls_group_data",
            "openmls_proposals",
            "openmls_own_leaf_nodes",
            "openmls_epoch_keys_pairs",
        ] {
            conn.execute(&format!("DELETE FROM {}", table), [])
                .map_err(|e| format!("Delete error in {}: {e}", table))?;
        }
        Ok(())
    }

    // ========================================================================
    // Identity Persistence
    // ========================================================================

    /// Store identity bytes in the database (replaces any previous identity).
    pub fn store_identity(&self, user_id: &str, identity_bytes: &[u8]) -> Result<(), String> {
        let conn = self.write_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO openmls_uniffi_identity (id, user_id, identity_bytes)
             VALUES (1, ?1, ?2)",
            rusqlite::params![user_id, identity_bytes],
        )
        .map_err(|e| format!("Store identity error: {e}"))?;
        Ok(())
    }

    /// Load identity bytes from the database.
    /// Returns (user_id, identity_bytes) or None if not stored.
    pub fn load_identity(&self) -> Result<Option<(String, Vec<u8>)>, String> {
        let conn = self.read_conn()?;
        let result = conn
            .query_row(
                "SELECT user_id, identity_bytes FROM openmls_uniffi_identity WHERE id = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|e| format!("Load identity error: {e}"))?;
        Ok(result)
    }

    /// Delete stored identity from the database.
    pub fn delete_identity(&self) -> Result<(), String> {
        let conn = self.write_conn()?;
        conn.execute("DELETE FROM openmls_uniffi_identity", [])
            .map_err(|e| format!("Delete identity error: {e}"))?;
        Ok(())
    }
}

impl OpenMlsProvider for PersistentCryptoProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

// ============================================================================
// Provider — UniFFI-exported wrapper
// ============================================================================

/// Crypto provider for MLS operations.
/// Wraps PersistentCryptoProvider in a Mutex for thread-safe UniFFI usage.
pub struct Provider {
    pub(crate) inner: Mutex<PersistentCryptoProvider>,
}

impl Provider {
    fn storage_error(context: &str, error: impl std::fmt::Display) -> crate::errors::MlsError {
        crate::mls_error!("{context}: {error}");
        crate::errors::MlsError::StorageError
    }

    /// Create a new in-memory provider (state lost when app closes).
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(PersistentCryptoProvider::new_in_memory().expect("in-memory DB")),
        }
    }

    /// Create a new persistent provider backed by a SQLite file at `db_path`.
    pub fn new_with_path(db_path: String) -> Result<Self, crate::errors::MlsError> {
        let persistent = PersistentCryptoProvider::new_with_path(&db_path).map_err(|e| {
            Self::storage_error(&format!("Provider.new_with_path({db_path}) failed"), e)
        })?;
        Ok(Self {
            inner: Mutex::new(persistent),
        })
    }

    // ========================================================================
    // Group Queries & Management (delegated to PersistentCryptoProvider)
    // ========================================================================

    /// List all group IDs (CIDs) stored in the SQLite database.
    pub fn stored_group_ids(&self) -> Result<Vec<String>, crate::errors::MlsError> {
        self.lock()
            .stored_group_ids()
            .map_err(|e| Self::storage_error("Provider.stored_group_ids failed", e))
    }

    /// Count the number of groups stored in the database.
    pub fn group_count(&self) -> Result<u32, crate::errors::MlsError> {
        self.lock()
            .group_count()
            .map_err(|e| Self::storage_error("Provider.group_count failed", e))
    }

    /// Delete all data for a specific group by CID.
    /// Call this after leaving or being removed from a group.
    pub fn delete_group(&self, cid: String) -> Result<(), crate::errors::MlsError> {
        self.lock()
            .delete_group(&cid)
            .map_err(|e| Self::storage_error(&format!("Provider.delete_group({cid}) failed"), e))
    }

    /// Delete all group data from the database.
    /// Call this on logout or full reset.
    pub fn delete_all_groups(&self) -> Result<(), crate::errors::MlsError> {
        self.lock()
            .delete_all_groups()
            .map_err(|e| Self::storage_error("Provider.delete_all_groups failed", e))
    }

    // ========================================================================
    // Identity Persistence
    // ========================================================================

    /// Store identity in the database. Replaces any previous identity.
    /// After calling this, you can restore the identity with `load_identity()`.
    pub fn store_identity(
        &self,
        user_id: String,
        identity_bytes: Vec<u8>,
    ) -> Result<(), crate::errors::MlsError> {
        self.lock()
            .store_identity(&user_id, &identity_bytes)
            .map_err(|e| {
                Self::storage_error(&format!("Provider.store_identity({user_id}) failed"), e)
            })
    }

    /// Load the stored identity from the database.
    /// Returns the identity bytes, or None if no identity is stored.
    pub fn load_identity(&self) -> Result<Option<Vec<u8>>, crate::errors::MlsError> {
        self.lock()
            .load_identity()
            .map(|opt| opt.map(|(_, bytes)| bytes))
            .map_err(|e| Self::storage_error("Provider.load_identity failed", e))
    }

    /// Delete the stored identity from the database.
    /// Call this on logout.
    pub fn delete_identity(&self) -> Result<(), crate::errors::MlsError> {
        self.lock()
            .delete_identity()
            .map_err(|e| Self::storage_error("Provider.delete_identity failed", e))
    }

    // ========================================================================
    // Internal
    // ========================================================================

    /// Get a reference to the inner crypto provider (locks the mutex).
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, PersistentCryptoProvider> {
        self.inner.lock().unwrap()
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}
