//! Binding-neutral SQLite-backed OpenMLS provider implementation.

use std::sync::atomic::{AtomicU64, Ordering};

use openmls::group::GroupId;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::OptionalExtension;
use serde::Serialize;

// Persisted schema name retained for compatibility with databases created by
// earlier UniFFI-only releases. It is a storage migration constraint, not a
// dependency on the UniFFI adapter.
const IDENTITY_TABLE: &str = "openmls_uniffi_identity";
static NEXT_IN_MEMORY_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
pub(crate) struct JsonCodec;

impl openmls_sqlite_storage::Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// Internal persistent provider hidden behind the binding-neutral `Provider`.
pub(crate) struct PersistentCryptoProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
    db_path: String,
}

impl PersistentCryptoProvider {
    pub(crate) fn new_with_path(db_path: &str) -> Result<Self, String> {
        let connection =
            Self::open_connection(db_path).map_err(|e| format!("Failed to open DB: {e}"))?;
        let mut storage = SqliteStorageProvider::new(connection);
        storage
            .run_migrations()
            .map_err(|e| format!("Failed to run migrations: {e}"))?;
        Self::create_identity_table(db_path)?;

        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
            db_path: db_path.to_string(),
        })
    }

    pub(crate) fn new_in_memory() -> Result<Self, String> {
        let id = NEXT_IN_MEMORY_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        let db_path = format!(
            "file:openmls_bindings_{}_{}?mode=memory&cache=shared",
            std::process::id(),
            id
        );
        Self::new_with_path(&db_path)
    }

    fn create_identity_table(db_path: &str) -> Result<(), String> {
        let conn = Self::open_connection(db_path).map_err(|e| format!("Failed to open DB: {e}"))?;
        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {IDENTITY_TABLE} (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    user_id TEXT NOT NULL,
                    identity_bytes BLOB NOT NULL
                )"
            ),
            [],
        )
        .map_err(|e| format!("Failed to create identity table: {e}"))?;
        Ok(())
    }

    fn open_connection(db_path: &str) -> rusqlite::Result<Connection> {
        if db_path.starts_with("file:") {
            Connection::open_with_flags(
                db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                    | rusqlite::OpenFlags::SQLITE_OPEN_URI,
            )
        } else {
            Connection::open(db_path)
        }
    }

    fn read_conn(&self) -> Result<Connection, String> {
        if self.db_path.starts_with("file:") {
            Self::open_connection(&self.db_path).map_err(|e| format!("DB open error: {e}"))
        } else {
            Connection::open_with_flags(&self.db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| format!("DB open error: {e}"))
        }
    }

    fn write_conn(&self) -> Result<Connection, String> {
        Self::open_connection(&self.db_path).map_err(|e| format!("DB open error: {e}"))
    }

    fn decode_group_id_blob(blob: &[u8]) -> Result<String, String> {
        let group_id: GroupId =
            serde_json::from_slice(blob).map_err(|e| format!("Invalid group ID: {e}"))?;
        String::from_utf8(group_id.to_vec()).map_err(|e| format!("Invalid CID encoding: {e}"))
    }

    fn encode_cid_as_blob(cid: &str) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&GroupId::from_slice(cid.as_bytes()))
            .map_err(|e| format!("Failed to encode CID: {e}"))
    }

    pub(crate) fn stored_group_ids(&self) -> Result<Vec<String>, String> {
        let conn = self.read_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT group_id FROM openmls_group_data WHERE data_type = 'group_state'",
            )
            .map_err(|e| format!("Prepare error: {e}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| format!("Query error: {e}"))?;

        let mut ids = Vec::new();
        for row in rows {
            let blob = row.map_err(|e| format!("Row error: {e}"))?;
            ids.push(Self::decode_group_id_blob(&blob)?);
        }
        Ok(ids)
    }

    pub(crate) fn group_count(&self) -> Result<u32, String> {
        self.read_conn()?
            .query_row(
                "SELECT COUNT(DISTINCT group_id) FROM openmls_group_data WHERE data_type = 'group_state'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("Query error: {e}"))
    }

    pub(crate) fn delete_group(&self, cid: &str) -> Result<(), String> {
        let mut conn = self.write_conn()?;
        let blob = Self::encode_cid_as_blob(cid)?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("Transaction error: {e}"))?;
        for table in &[
            "openmls_group_data",
            "openmls_proposals",
            "openmls_own_leaf_nodes",
            "openmls_epoch_keys_pairs",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE group_id = ?1"),
                rusqlite::params![blob],
            )
            .map_err(|e| format!("Delete error in {table}: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("Commit delete transaction error: {e}"))
    }

    pub(crate) fn delete_all_groups(&self) -> Result<(), String> {
        let mut conn = self.write_conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("Transaction error: {e}"))?;
        for table in &[
            "openmls_group_data",
            "openmls_proposals",
            "openmls_own_leaf_nodes",
            "openmls_epoch_keys_pairs",
        ] {
            tx.execute(&format!("DELETE FROM {table}"), [])
                .map_err(|e| format!("Delete error in {table}: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("Commit delete transaction error: {e}"))
    }

    pub(crate) fn store_identity(
        &self,
        user_id: &str,
        identity_bytes: &[u8],
    ) -> Result<(), String> {
        self.write_conn()?
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO {IDENTITY_TABLE} (id, user_id, identity_bytes)
                     VALUES (1, ?1, ?2)"
                ),
                rusqlite::params![user_id, identity_bytes],
            )
            .map_err(|e| format!("Store identity error: {e}"))?;
        Ok(())
    }

    pub(crate) fn load_identity(&self) -> Result<Option<(String, Vec<u8>)>, String> {
        self.read_conn()?
            .query_row(
                &format!("SELECT user_id, identity_bytes FROM {IDENTITY_TABLE} WHERE id = 1"),
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|e| format!("Load identity error: {e}"))
    }

    pub(crate) fn delete_identity(&self) -> Result<(), String> {
        self.write_conn()?
            .execute(&format!("DELETE FROM {IDENTITY_TABLE}"), [])
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
