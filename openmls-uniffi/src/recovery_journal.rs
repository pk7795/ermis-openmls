//! Indexed durable journal shared by both mobile SDKs. Secret payloads must be protected.
use crate::MlsError;
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryJournalEntry {
    pub key: String,
    pub kind: String,
    pub cid: String,
    pub group_generation: u64,
    pub epoch: u64,
    pub scope: String,
    pub payload: Vec<u8>,
    pub status: String,
    pub retry_count: u32,
    pub created_at: i64,
    pub next_retry_at: i64,
    pub last_error: Option<String>,
}
pub struct RecoveryJournal {
    db: Mutex<Connection>,
}
fn storage(_: rusqlite::Error) -> MlsError {
    MlsError::StorageError
}
fn read(r: &rusqlite::Row<'_>) -> rusqlite::Result<RecoveryJournalEntry> {
    Ok(RecoveryJournalEntry {
        key: r.get(0)?,
        kind: r.get(1)?,
        cid: r.get(2)?,
        group_generation: r.get(3)?,
        epoch: r.get(4)?,
        scope: r.get(5)?,
        payload: r.get(6)?,
        status: r.get(7)?,
        retry_count: r.get(8)?,
        created_at: r.get(9)?,
        next_retry_at: r.get(10)?,
        last_error: r.get(11)?,
    })
}
const COLUMNS: &str = "key,kind,cid,generation,epoch,scope,payload,status,retries,created_at,next_retry_at,last_error";
fn write(db: &Connection, e: &RecoveryJournalEntry, replace: bool) -> Result<usize, MlsError> {
    if e.payload.len() > 16 * 1024 * 1024
        || e.group_generation > i64::MAX as u64
        || e.epoch > i64::MAX as u64
    {
        return Err(MlsError::InvalidState);
    }
    db.execute(&format!("INSERT {} INTO recovery_work ({COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)", if replace { "OR REPLACE" } else { "OR IGNORE" }),
    params![e.key,e.kind,e.cid,e.group_generation,e.epoch,e.scope,e.payload,e.status,e.retry_count,e.created_at,e.next_retry_at,e.last_error]).map_err(storage)
}
impl RecoveryJournal {
    pub fn new(path: String) -> Result<Self, MlsError> {
        let db = Connection::open(path).map_err(storage)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS recovery_work (key TEXT PRIMARY KEY,kind TEXT NOT NULL,cid TEXT NOT NULL,generation INTEGER NOT NULL,epoch INTEGER NOT NULL,scope TEXT NOT NULL,payload BLOB NOT NULL,status TEXT NOT NULL,retries INTEGER NOT NULL,created_at INTEGER NOT NULL,next_retry_at INTEGER NOT NULL,last_error TEXT);
            CREATE INDEX IF NOT EXISTS recovery_due ON recovery_work(kind,status,next_retry_at,key);
            CREATE INDEX IF NOT EXISTS recovery_channel ON recovery_work(kind,status,cid,next_retry_at,key);
            PRAGMA user_version=1;").map_err(storage)?;
        Ok(Self { db: Mutex::new(db) })
    }
    pub fn insert_if_absent(&self, entry: RecoveryJournalEntry) -> Result<bool, MlsError> {
        let db = self.db.lock().map_err(|_| MlsError::StorageError)?;
        Ok(write(&db, &entry, false)? == 1)
    }
    pub fn put(&self, entry: RecoveryJournalEntry) -> Result<(), MlsError> {
        let db = self.db.lock().map_err(|_| MlsError::StorageError)?;
        write(&db, &entry, true)?;
        Ok(())
    }
    pub fn get(&self, key: String) -> Result<Option<RecoveryJournalEntry>, MlsError> {
        self.db
            .lock()
            .map_err(|_| MlsError::StorageError)?
            .query_row(
                &format!("SELECT {COLUMNS} FROM recovery_work WHERE key=?1"),
                [key],
                read,
            )
            .optional()
            .map_err(storage)
    }
    pub fn page(
        &self,
        kind: String,
        status: String,
        now: i64,
        cid: Option<String>,
        after_key: Option<String>,
        limit: u32,
    ) -> Result<Vec<RecoveryJournalEntry>, MlsError> {
        let db = self.db.lock().map_err(|_| MlsError::StorageError)?;
        let (after_time, after_id) = match after_key.as_deref() {
            None => (i64::MIN, ""),
            Some(cursor) => {
                let (t, k) = cursor.split_once('|').ok_or(MlsError::InvalidState)?;
                (t.parse::<i64>().map_err(|_| MlsError::InvalidState)?, k)
            }
        };
        let clause = if cid.is_some() { "AND cid=?7" } else { "" };
        let mut q=db.prepare(&format!("SELECT {COLUMNS} FROM recovery_work WHERE kind=?1 AND status=?2 AND (next_retry_at,key)>(?3,?4) AND next_retry_at<=?5 {clause} ORDER BY next_retry_at,key LIMIT ?6")).map_err(storage)?;
        let map = if let Some(cid) = cid {
            q.query_map(
                params![
                    kind,
                    status,
                    after_time,
                    after_id,
                    now,
                    limit.clamp(1, 50),
                    cid
                ],
                read,
            )
        } else {
            q.query_map(
                params![kind, status, after_time, after_id, now, limit.clamp(1, 50)],
                read,
            )
        }
        .map_err(storage)?;
        // Bound page memory as well as row count. A single entry remains readable.
        let mut result = Vec::new();
        let mut bytes = 0usize;
        for item in map {
            let item = item.map_err(storage)?;
            if !result.is_empty() && bytes.saturating_add(item.payload.len()) > 8 * 1024 * 1024 {
                break;
            }
            bytes += item.payload.len();
            result.push(item);
        }
        Ok(result)
    }
    pub fn remove(&self, key: String) -> Result<(), MlsError> {
        self.db
            .lock()
            .map_err(|_| MlsError::StorageError)?
            .execute("DELETE FROM recovery_work WHERE key=?1", [key])
            .map_err(storage)?;
        Ok(())
    }
    pub fn commit_upload(
        &self,
        pending_key: String,
        ack: RecoveryJournalEntry,
        checkpoint: Option<RecoveryJournalEntry>,
    ) -> Result<(), MlsError> {
        if ack.key == pending_key
            || ack.kind != "ack"
            || !["uploaded", "idempotent", "duplicate_cap"].contains(&ack.status.as_str())
        {
            return Err(MlsError::InvalidState);
        }
        let mut db = self.db.lock().map_err(|_| MlsError::StorageError)?;
        let tx = db.transaction().map_err(storage)?;
        let item = tx
            .query_row(
                &format!("SELECT {COLUMNS} FROM recovery_work WHERE key=?1"),
                [&pending_key],
                read,
            )
            .optional()
            .map_err(storage)?
            .ok_or(MlsError::InvalidState)?;
        if item.kind != "upload"
            || item.cid != ack.cid
            || item.group_generation != ack.group_generation
            || item.epoch != ack.epoch
            || item.scope != ack.scope
        {
            return Err(MlsError::InvalidState);
        }
        write(&tx, &ack, true)?;
        if let Some(cp) = checkpoint {
            if cp.kind != "checkpoint"
                || cp.cid != item.cid
                || cp.group_generation != item.group_generation
                || cp.epoch != item.epoch
                || cp.scope != item.scope
            {
                return Err(MlsError::InvalidState);
            }
            write(&tx, &cp, true)?;
        }
        tx.execute("DELETE FROM recovery_work WHERE key=?1", [pending_key])
            .map_err(storage)?;
        tx.commit().map_err(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(key: &str) -> RecoveryJournalEntry {
        RecoveryJournalEntry {
            key: key.into(),
            kind: "upload".into(),
            cid: "messaging:test".into(),
            group_generation: 3,
            epoch: 7,
            scope: "account_owned".into(),
            payload: vec![1, 2, 3],
            status: "queued".into(),
            retry_count: 0,
            created_at: 1,
            next_retry_at: 0,
            last_error: None,
        }
    }
    #[test]
    fn ack_and_removal_are_atomic_across_reopen() {
        let path = std::env::temp_dir().join(format!(
            "recovery-journal-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let name = path.to_string_lossy().to_string();
        {
            let journal = RecoveryJournal::new(name.clone()).unwrap();
            assert!(journal.insert_if_absent(row("pending")).unwrap());
            let mut changed = row("pending");
            changed.payload = vec![9];
            assert!(!journal.insert_if_absent(changed).unwrap());
        }
        {
            let journal = RecoveryJournal::new(name.clone()).unwrap();
            assert_eq!(
                journal.get("pending".into()).unwrap().unwrap().payload,
                vec![1, 2, 3]
            );
            let mut ack = row("ack");
            ack.kind = "ack".into();
            ack.status = "uploaded".into();
            let mut wrong = row("checkpoint");
            wrong.kind = "checkpoint".into();
            wrong.scope = "group_sponsored".into();
            assert!(journal
                .commit_upload("pending".into(), ack.clone(), Some(wrong))
                .is_err());
            assert!(journal.get("ack".into()).unwrap().is_none());
            assert!(journal.get("pending".into()).unwrap().is_some());
            journal.commit_upload("pending".into(), ack, None).unwrap();
        }
        let journal = RecoveryJournal::new(name).unwrap();
        assert!(journal.get("pending".into()).unwrap().is_none());
        assert_eq!(
            journal.get("ack".into()).unwrap().unwrap().status,
            "uploaded"
        );
        drop(journal);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn page_payload_budget_limits_mobile_memory() {
        let journal = RecoveryJournal::new(":memory:".into()).unwrap();
        for i in 0..12 {
            let mut item = row(&format!("{i:03}"));
            item.payload = vec![0; 1024 * 1024];
            journal.put(item).unwrap();
        }
        let page = journal
            .page("upload".into(), "queued".into(), 0, None, None, 50)
            .unwrap();
        assert_eq!(page.len(), 8);
    }
    #[test]
    fn due_paging_is_bounded_and_paused_work_is_preserved() {
        let journal = RecoveryJournal::new(":memory:".into()).unwrap();
        for i in 0..121 {
            let mut item = row(&format!("{i:03}"));
            item.next_retry_at = (i / 3) as i64;
            journal.put(item).unwrap();
        }
        let mut denied = row("denied");
        denied.status = "permission_denied".into();
        journal.put(denied.clone()).unwrap();
        let first = journal
            .page("upload".into(), "queued".into(), 100, None, None, 1000)
            .unwrap();
        assert_eq!(first.len(), 50);
        let last = first.last().unwrap();
        let second = journal
            .page(
                "upload".into(),
                "queued".into(),
                100,
                None,
                Some(format!("{}|{}", last.next_retry_at, last.key)),
                50,
            )
            .unwrap();
        assert_eq!(second.len(), 50);
        assert!(second.iter().all(|row| !first.contains(row)));
        assert_eq!(journal.get("denied".into()).unwrap(), Some(denied));
        assert_eq!(
            journal
                .page("upload".into(), "queued".into(), 0, None, None, 50)
                .unwrap()
                .len(),
            3
        );
    }
}
