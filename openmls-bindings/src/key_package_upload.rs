//! Exact upload recovery. The public journal and private bundles share one
//! native connection/transaction. Neither this lock nor a transaction spans HTTP.
use crate::{Identity, MlsError, Provider};
use openmls_traits::{random::OpenMlsRand, OpenMlsProvider};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

impl crate::storage::PersistentCryptoProvider {
    pub(crate) fn key_package_upload_provider_id(&self) -> crate::MlsResult<String> {
        let conn = self.storage().connection();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS openmls_upload_provider (
                id INTEGER PRIMARY KEY CHECK(id=1), instance BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS openmls_upload_batches (
                operation_id TEXT PRIMARY KEY, version INTEGER NOT NULL,
                signer BLOB NOT NULL, scope TEXT NOT NULL, count INTEGER NOT NULL,
                payload BLOB NOT NULL, payload_sha256 BLOB NOT NULL);",
        )
        .map_err(|_| MlsError::StorageError)?;
        let random = self
            .rand()
            .random_vec(32)
            .map_err(|_| MlsError::CryptoError)?;
        conn.execute(
            "INSERT OR IGNORE INTO openmls_upload_provider(id,instance) VALUES(1,?1)",
            [random],
        )
        .map_err(|_| MlsError::StorageError)?;
        let instance: Vec<u8> = conn
            .query_row(
                "SELECT instance FROM openmls_upload_provider WHERE id=1",
                [],
                |r| r.get(0),
            )
            .map_err(|_| MlsError::StorageError)?;
        if instance.len() != 32 {
            return Err(MlsError::StorageCorruption);
        }
        Ok(hex::encode(instance))
    }
}

impl Provider {
    /// Stable per-native-database identity, persisted before a public preparing
    /// job. A replacement database cannot be mistaken for rolled-back work.
    pub fn key_package_upload_provider_id(&self) -> crate::MlsResult<String> {
        self.lock()?.key_package_upload_provider_id()
    }
}

impl Identity {
    /// Generate once or recover the immutable exact public batch. An absent
    /// journal authorizes generation only in the original bound native instance.
    pub fn prepare_key_package_upload(
        &self,
        provider: &Provider,
        operation_id: String,
        scope: String,
        expected_provider_id: String,
        count: u32,
    ) -> crate::MlsResult<Vec<Vec<u8>>> {
        let digest = |s: &str| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit());
        if !(1..=100).contains(&count)
            || !digest(&scope)
            || !digest(&expected_provider_id)
            || operation_id.len() != 36
            || operation_id.bytes().enumerate().any(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c != b'-'
                } else {
                    !c.is_ascii_hexdigit()
                }
            })
        {
            return Err(MlsError::SerializationError);
        }
        let operation_id = operation_id.to_ascii_lowercase();
        let guard = provider.lock()?;
        if guard.key_package_upload_provider_id()? != expected_provider_id {
            return Err(MlsError::InvalidState);
        }
        guard.transaction(|native| {
            let conn = native.storage().connection();
            type Saved = (i64, Vec<u8>, String, u32, Vec<u8>, Vec<u8>);
            let saved: Option<Saved> = conn.query_row(
                "SELECT version,signer,scope,count,payload,payload_sha256 FROM openmls_upload_batches WHERE operation_id=?1",
                [&operation_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
            ).optional().map_err(|_| MlsError::StorageError)?;
            if let Some((version, signer, saved_scope, saved_count, payload, hash)) = saved {
                if version != 1 || signer != self.signature_public_key() || saved_scope != scope || saved_count != count {
                    return Err(MlsError::InvalidState);
                }
                if payload.len() > 3 * 1024 * 1024 || Sha256::digest(&payload).as_slice() != hash {
                    return Err(MlsError::StorageCorruption);
                }
                let batch: Vec<Vec<u8>> = serde_json::from_slice(&payload).map_err(|_| MlsError::StorageCorruption)?;
                if batch.len() != count as usize || batch.iter().any(Vec::is_empty) {
                    return Err(MlsError::StorageCorruption);
                }
                return Ok(batch);
            }
            #[cfg(test)]
            crash_at("before_generation");
            let batch = (0..count).map(|_| self.key_package_in(native)?.to_bytes()).collect::<crate::MlsResult<Vec<_>>>()?;
            #[cfg(test)]
            crash_at("after_private");
            let payload = serde_json::to_vec(&batch).map_err(|_| MlsError::SerializationError)?;
            if payload.len() > 3 * 1024 * 1024 { return Err(MlsError::SerializationError); }
            let hash = Sha256::digest(&payload).to_vec();
            conn.execute("INSERT INTO openmls_upload_batches(operation_id,version,signer,scope,count,payload,payload_sha256) VALUES(?1,1,?2,?3,?4,?5,?6)",
                params![operation_id,self.signature_public_key(),scope,count,payload,hash]).map_err(|_| MlsError::StorageError)?;
            #[cfg(test)]
            crash_at("after_journal");
            Ok(batch)
        }).map(|batch| {
            #[cfg(test)]
            crash_at("after_commit");
            batch
        })
    }
}

#[cfg(test)]
fn crash_at(stage: &str) {
    if std::env::var("OPENMLS_UPLOAD_TEST_CRASH").as_deref() == Ok(stage) {
        std::process::exit(73);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Group, KeyPackage};
    use std::error::Error;
    const OP: &str = "01234567-1234-4000-8000-123456789abc";
    fn scope() -> String {
        "a".repeat(64)
    }
    fn prepare(p: &Provider, i: &Identity, count: u32) -> crate::MlsResult<Vec<Vec<u8>>> {
        i.prepare_key_package_upload(
            p,
            OP.into(),
            scope(),
            p.key_package_upload_provider_id()?,
            count,
        )
    }
    #[test]
    fn exact_batch_reopen_replay_and_consumed_package_is_never_regenerated(
    ) -> Result<(), Box<dyn Error>> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("provider.db");
        let p = Provider::new_with_path(path.to_string_lossy().into())?;
        let i = Identity::new(&p, "recipient".into())?;
        p.store_identity(i.user_id(), i.to_bytes()?)?;
        let batch = prepare(&p, &i, 3)?;
        let reference = KeyPackage::from_bytes(batch[0].clone())?.hash_ref(&p)?;
        let sender = Provider::new();
        let si = Identity::new(&sender, "sender".into())?;
        let g = Group::create_with_cid(&sender, &si, "team:upload".into())?;
        let welcome = g
            .add_members(
                &sender,
                &si,
                vec![KeyPackage::from_bytes(batch[0].clone())?],
            )?
            .welcome
            .ok_or("missing welcome")?;
        Group::join_with_welcome(&p, welcome, None)?;
        assert!(!i.owns_key_package_ref(&p, reference.clone())?);
        drop(i);
        drop(p);
        let p = Provider::new_with_path(path.to_string_lossy().into())?;
        let i = Identity::from_bytes(&p, p.load_identity()?.ok_or("missing identity")?)?;
        assert_eq!(prepare(&p, &i, 3)?, batch);
        assert!(!i.owns_key_package_ref(&p, reference)?);
        assert!(prepare(&p, &i, 2).is_err());
        let different = Identity::new(&p, "other".into())?;
        assert!(prepare(&p, &different, 3).is_err());
        let id = p.key_package_upload_provider_id()?;
        assert!(i
            .prepare_key_package_upload(&p, OP.into(), "b".repeat(64), id.clone(), 3)
            .is_err());
        assert!(i
            .prepare_key_package_upload(&Provider::new(), OP.into(), scope(), id, 3)
            .is_err());
        Ok(())
    }
    #[test]
    fn journal_write_failure_rolls_back_every_private_bundle() -> Result<(), Box<dyn Error>> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("provider.db");
        let p = Provider::new_with_path(path.to_string_lossy().into())?;
        let i = Identity::new(&p, "recipient".into())?;
        p.key_package_upload_provider_id()?;
        let db = rusqlite::Connection::open(&path)?;
        db.execute_batch("CREATE TRIGGER fail_upload BEFORE INSERT ON openmls_upload_batches BEGIN SELECT RAISE(ABORT,'injected');END;")?;
        assert!(prepare(&p, &i, 10).is_err());
        let count: i64 = db.query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
            r.get(0)
        })?;
        assert_eq!(count, 0);
        db.execute_batch("DROP TRIGGER fail_upload")?;
        assert_eq!(prepare(&p, &i, 10)?.len(), 10);
        Ok(())
    }
    #[test]
    fn corrupt_partial_or_hash_mismatched_journal_fails_closed_without_generating(
    ) -> Result<(), Box<dyn Error>> {
        for fault in ["hash", "truncated", "count", "version", "signer"] {
            let tmp = tempfile::tempdir()?;
            let path = tmp.path().join("provider.db");
            let p = Provider::new_with_path(path.to_string_lossy().into())?;
            let i = Identity::new(&p, "recipient".into())?;
            prepare(&p, &i, 2)?;
            let db = rusqlite::Connection::open(&path)?;
            let sql = match fault {
                "hash" => "UPDATE openmls_upload_batches SET payload_sha256=zeroblob(32)",
                "truncated" => "UPDATE openmls_upload_batches SET payload=x'5b'",
                "count" => "UPDATE openmls_upload_batches SET count=99",
                "version" => "UPDATE openmls_upload_batches SET version=99",
                _ => "UPDATE openmls_upload_batches SET signer=x'00'",
            };
            db.execute_batch(sql)?;
            assert!(prepare(&p, &i, 2).is_err(), "{fault}");
            let count: i64 =
                db.query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
                    r.get(0)
                })?;
            assert_eq!(count, 2);
            let journal: i64 =
                db.query_row("SELECT count(*) FROM openmls_upload_batches", [], |r| {
                    r.get(0)
                })?;
            assert_eq!(journal, 1);
        }
        Ok(())
    }
    #[test]
    fn crash_child() -> Result<(), Box<dyn Error>> {
        let Ok(path) = std::env::var("OPENMLS_UPLOAD_TEST_DB") else {
            return Ok(());
        };
        let p = Provider::new_with_path(path)?;
        let i = Identity::from_bytes(&p, p.load_identity()?.ok_or("missing identity")?)?;
        prepare(&p, &i, 3)?;
        Err("child did not reach crash point".into())
    }
    #[test]
    fn process_death_at_all_generation_boundaries_recovers_exactly_one_batch(
    ) -> Result<(), Box<dyn Error>> {
        for stage in [
            "before_generation",
            "after_private",
            "after_journal",
            "after_commit",
        ] {
            let tmp = tempfile::tempdir()?;
            let path = tmp.path().join("provider.db");
            let p = Provider::new_with_path(path.to_string_lossy().into())?;
            let i = Identity::new(&p, "recipient".into())?;
            p.store_identity(i.user_id(), i.to_bytes()?)?;
            let instance = p.key_package_upload_provider_id()?;
            drop(i);
            drop(p);
            let status = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "key_package_upload::tests::crash_child",
                    "--nocapture",
                ])
                .env("OPENMLS_UPLOAD_TEST_DB", &path)
                .env("OPENMLS_UPLOAD_TEST_CRASH", stage)
                .status()?;
            assert_eq!(status.code(), Some(73), "{stage}");
            let db = rusqlite::Connection::open(&path)?;
            let private: i64 =
                db.query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
                    r.get(0)
                })?;
            let journals: i64 =
                db.query_row("SELECT count(*) FROM openmls_upload_batches", [], |r| {
                    r.get(0)
                })?;
            assert_eq!(
                private,
                if stage == "after_commit" { 3 } else { 0 },
                "{stage}"
            );
            assert_eq!(
                journals,
                if stage == "after_commit" { 1 } else { 0 },
                "{stage}"
            );
            let p = Provider::new_with_path(path.to_string_lossy().into())?;
            assert_eq!(p.key_package_upload_provider_id()?, instance);
            let i = Identity::from_bytes(&p, p.load_identity()?.ok_or("missing identity")?)?;
            let batch = prepare(&p, &i, 3)?;
            assert_eq!(prepare(&p, &i, 3)?, batch);
            for bytes in batch {
                let reference = KeyPackage::from_bytes(bytes)?.hash_ref(&p)?;
                assert!(i.owns_key_package_ref(&p, reference)?);
            }
            let private: i64 =
                db.query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
                    r.get(0)
                })?;
            assert_eq!(private, 3, "{stage}");
        }
        Ok(())
    }
}
