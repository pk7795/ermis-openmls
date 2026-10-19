//! Binding-neutral SQLite-backed OpenMLS provider implementation.

use std::{
    cell::Cell,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::errors::MlsError;

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
    available: Cell<bool>,
}

impl PersistentCryptoProvider {
    pub(crate) fn new_with_path(db_path: &str) -> Result<Self, String> {
        let connection =
            Self::open_connection(db_path).map_err(|e| format!("Failed to open DB: {e}"))?;
        let mut storage = SqliteStorageProvider::new(connection);
        storage
            .run_migrations()
            .map_err(|e| format!("Failed to run migrations: {e}"))?;
        Self::create_identity_table(storage.connection())?;

        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
            available: Cell::new(true),
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

    fn create_identity_table(conn: &Connection) -> Result<(), String> {
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

    pub(crate) fn is_available(&self) -> bool {
        self.available.get()
    }

    /// Called only while holding the provider mutex. All MLS and helper writes
    /// use storage.connection(); a result is published only after RELEASE.
    pub(crate) fn transaction<T>(
        &self,
        action: impl FnOnce(&Self) -> crate::MlsResult<T>,
    ) -> crate::MlsResult<T> {
        if !self.available.get() {
            return Err(MlsError::StorageError);
        }
        let conn = self.storage.connection();
        conn.execute_batch("SAVEPOINT bindings_operation")
            .map_err(|_| MlsError::StorageError)?;
        match action(self) {
            Ok(result) => {
                if conn.execute_batch("RELEASE bindings_operation").is_err() {
                    // A failed commit can be indeterminate. Never reuse this handle.
                    self.available.set(false);
                    let _ = conn.execute_batch(
                        "ROLLBACK TO bindings_operation; RELEASE bindings_operation",
                    );
                    return Err(MlsError::StorageError);
                }
                Ok(result)
            }
            Err(error) => {
                if conn
                    .execute_batch("ROLLBACK TO bindings_operation; RELEASE bindings_operation")
                    .is_err()
                {
                    self.available.set(false);
                    return Err(MlsError::StorageError);
                }
                Err(error)
            }
        }
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
        let conn = self.storage.connection();
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
        self.storage.connection()
            .query_row(
                "SELECT COUNT(DISTINCT group_id) FROM openmls_group_data WHERE data_type = 'group_state'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("Query error: {e}"))
    }

    pub(crate) fn delete_group(&self, cid: &str) -> Result<(), String> {
        let blob = Self::encode_cid_as_blob(cid)?;
        self.delete_group_rows(Some(&blob))
    }

    pub(crate) fn delete_all_groups(&self) -> Result<(), String> {
        self.delete_group_rows(None)
    }

    fn delete_group_rows(&self, blob: Option<&[u8]>) -> Result<(), String> {
        self.transaction(|provider| {
            let conn = provider.storage.connection();
            for table in &[
                "openmls_group_data",
                "openmls_proposals",
                "openmls_own_leaf_nodes",
                "openmls_epoch_keys_pairs",
            ] {
                let result = match blob {
                    Some(blob) => {
                        conn.execute(&format!("DELETE FROM {table} WHERE group_id = ?1"), [blob])
                    }
                    None => conn.execute(&format!("DELETE FROM {table}"), []),
                };
                result.map_err(|_| MlsError::StorageError)?;
            }
            Ok(())
        })
        .map_err(|error| error.to_string())
    }

    pub(crate) fn store_identity(
        &self,
        user_id: &str,
        identity_bytes: &[u8],
    ) -> Result<(), String> {
        self.storage
            .connection()
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
        self.storage
            .connection()
            .query_row(
                &format!("SELECT user_id, identity_bytes FROM {IDENTITY_TABLE} WHERE id = 1"),
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|e| format!("Load identity error: {e}"))
    }

    pub(crate) fn delete_identity(&self) -> Result<(), String> {
        self.storage
            .connection()
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

#[cfg(test)]
mod atomicity_tests {
    use super::*;
    use crate::{Group, Identity, Provider};
    use openmls::prelude::{MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, StagedWelcome};
    use tls_codec::Deserialize;

    #[test]
    fn helper_writes_and_reads_share_the_operation_connection(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let provider = Provider::new();
        let guard = provider.lock()?;
        let result: crate::MlsResult<()> = guard.transaction(|persistent| {
            persistent
                .store_identity("first", b"durable")
                .map_err(|_| MlsError::StorageError)?;
            assert_eq!(
                persistent
                    .load_identity()
                    .map_err(|_| MlsError::StorageError)?,
                Some(("first".into(), b"durable".to_vec()))
            );
            Err(MlsError::InvalidState)
        });
        assert!(matches!(result, Err(MlsError::InvalidState)));
        assert_eq!(guard.load_identity()?, None);
        // A nested helper savepoint must not commit the outer operation.
        let result: crate::MlsResult<()> = guard.transaction(|persistent| {
            persistent
                .store_identity("outer", b"value")
                .map_err(|_| MlsError::StorageError)?;
            persistent
                .delete_all_groups()
                .map_err(|_| MlsError::StorageError)?;
            Err(MlsError::InvalidState)
        });
        assert!(result.is_err());
        assert_eq!(guard.load_identity()?, None);
        Ok(())
    }

    #[test]
    fn lost_transaction_and_failed_commit_make_provider_unavailable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for success in [false, true] {
            let provider = Provider::new();
            {
                let guard = provider.lock()?;
                let result = guard.transaction(|persistent| {
                    persistent
                        .storage
                        .connection()
                        .execute_batch("ROLLBACK")
                        .map_err(|_| MlsError::StorageError)?;
                    if success {
                        Ok(())
                    } else {
                        Err(MlsError::InvalidState)
                    }
                });
                assert!(matches!(result, Err(MlsError::StorageError)));
            }
            assert!(matches!(
                provider.load_identity(),
                Err(MlsError::StorageError)
            ));
            assert!(matches!(
                provider.group_count(),
                Err(MlsError::StorageError)
            ));
        }
        Ok(())
    }

    #[test]
    fn poisoned_provider_never_recovers_mutated_state() -> Result<(), Box<dyn std::error::Error>> {
        let provider = Provider::new();
        let mutex = provider.inner_for_poison_test()?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Ok(_guard) = mutex.lock() {
                panic!("intentional mutex poison injection");
            }
        }));
        assert!(result.is_err());
        assert!(matches!(
            provider.load_identity(),
            Err(MlsError::StorageError)
        ));
        Ok(())
    }

    #[test]
    fn crash_child() -> Result<(), Box<dyn std::error::Error>> {
        let Some(path) = std::env::var_os("LOR_CRASH_DATABASE") else {
            return Ok(());
        };
        let welcome_path = std::env::var_os("LOR_CRASH_WELCOME").ok_or("missing child fixture")?;
        let provider = Provider::new_with_path(path.to_string_lossy().into())?;
        let welcome =
            match MlsMessageIn::tls_deserialize_exact(&std::fs::read(welcome_path)?)?.extract() {
                MlsMessageBodyIn::Welcome(welcome) => welcome,
                _ => return Err("wrong fixture".into()),
            };
        let guard = provider.lock()?;
        guard.transaction(|persistent| {
            let staged = StagedWelcome::new_from_welcome(
                persistent,
                &MlsGroupJoinConfig::default(),
                welcome,
                None,
            )
            .map_err(|_| MlsError::InternalError)?;
            let _group = staged
                .into_group(persistent)
                .map_err(|_| MlsError::InternalError)?;
            // Simulate process death after KP deletion and every group write,
            // before the provider publishes a committed Group.
            std::process::exit(73);
        })?;
        Ok(())
    }

    #[test]
    fn process_death_before_commit_restores_private_bundle_after_restart(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("crash.sqlite");
        let welcome_path = tmp.path().join("welcome.bin");
        let provider = Provider::new_with_path(path.to_string_lossy().into())?;
        let bob = Identity::new(&provider, "bob".into())?;
        let identity_bytes = bob.to_bytes()?;
        let kp = bob.key_package(&provider)?;
        let reference = kp.hash_ref(&provider)?;
        let inviter_provider = Provider::new();
        let inviter = Identity::new(&inviter_provider, "alice".into())?;
        let group = Group::create_with_cid(&inviter_provider, &inviter, "team:crash".into())?;
        let welcome = group
            .add_members(&inviter_provider, &inviter, vec![kp])?
            .welcome
            .ok_or("no Welcome")?;
        std::fs::write(&welcome_path, &welcome)?;
        drop(provider);
        let result = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "storage::atomicity_tests::crash_child",
                "--nocapture",
            ])
            .env("LOR_CRASH_DATABASE", &path)
            .env("LOR_CRASH_WELCOME", &welcome_path)
            .output()?;
        assert_eq!(
            result.status.code(),
            Some(73),
            "child must exit at the crash point"
        );
        let provider = Provider::new_with_path(path.to_string_lossy().into())?;
        let bob = Identity::from_bytes(&provider, identity_bytes)?;
        assert!(bob.owns_key_package_ref(&provider, reference.clone())?);
        assert_eq!(provider.group_count()?, 0);
        Group::join_with_welcome(&provider, welcome, None)?;
        assert!(!bob.owns_key_package_ref(&provider, reference)?);
        Ok(())
    }
}
