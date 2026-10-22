use openmls_bindings_core::{Group, Identity, Provider};

#[test]
fn independent_members_have_the_same_complete_context() -> Result<(), Box<dyn std::error::Error>> {
    let alice_provider = Provider::new();
    let bob_provider = Provider::new();
    let alice = Identity::new(&alice_provider, "alice".into())?;
    let bob = Identity::new(&bob_provider, "bob".into())?;
    let founder = Group::create_with_cid(&alice_provider, &alice, "team:context".into())?;
    let before = founder.public_context_fingerprint()?;
    let bundle = founder.add_members(&alice_provider, &alice, vec![bob.key_package(&bob_provider)?])?;
    assert!(founder.public_context_fingerprint().is_err(), "Pending commit is not an operational branch proof");
    founder.merge_pending_commit(&alice_provider)?;
    let recipient = Group::join_with_welcome(&bob_provider, bundle.welcome.ok_or("missing Welcome")?, Some(founder.export_ratchet_tree()))?;
    assert_ne!(before, founder.public_context_fingerprint()?);
    assert_eq!(32, recipient.public_context_fingerprint()?.len());
    assert_eq!(founder.public_context_fingerprint()?, recipient.public_context_fingerprint()?);
    Ok(())
}

#[test]
fn equal_cid_epoch_and_account_on_an_independent_fork_are_not_proof() -> Result<(), Box<dyn std::error::Error>> {
    let one = Provider::new(); let two = Provider::new();
    let first = Identity::new(&one, "same-account".into())?;
    let second = Identity::new(&two, "same-account".into())?;
    let a = Group::create_with_cid(&one, &first, "team:same".into())?;
    let b = Group::create_with_cid(&two, &second, "team:same".into())?;
    assert_eq!(a.epoch(), b.epoch()); assert_eq!(a.group_id(), b.group_id());
    assert_ne!(a.public_context_fingerprint()?, b.public_context_fingerprint()?);
    Ok(())
}

#[test]
fn fingerprint_survives_a_real_sqlite_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?; let path = dir.path().join("context.sqlite").to_string_lossy().into_owned();
    let expected;
    {
        let provider = Provider::new_with_path(path.clone())?;
        let identity = Identity::new(&provider, "persisted".into())?;
        let group = Group::create_with_cid(&provider, &identity, "team:persisted".into())?;
        group.save_state(&provider)?; expected = group.public_context_fingerprint()?;
    }
    let reopened = Provider::new_with_path(path)?;
    let group = Group::load_from_storage(&reopened, "team:persisted".into())?;
    assert_eq!(expected, group.public_context_fingerprint()?);
    Ok(())
}

#[test]
fn same_signer_external_commit_is_verified_without_mutating_retained_welcome() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("welcome.sqlite").to_string_lossy().into_owned();
    let original = Provider::new_with_path(path.clone())?;
    let alice_provider = Provider::new(); let alice = Identity::new(&alice_provider, "alice".into())?;
    let bob = Identity::new(&original, "bob".into())?;
    let group = Group::create_with_cid(&alice_provider, &alice, "team:staged".into())?;
    let add = group.add_members(&alice_provider, &alice, vec![bob.key_package(&original)?])?;
    group.merge_pending_commit(&alice_provider)?;
    let welcome = Group::join_with_welcome(&original, add.welcome.ok_or("missing Welcome")?, Some(group.export_ratchet_tree()))?;
    welcome.save_state(&original)?;
    let history = group.create_message(&alice_provider, &alice, b"before join".to_vec())?;
    let candidate_provider = Provider::new();
    let candidate_identity = Identity::from_bytes(&candidate_provider, bob.to_bytes()?)?;
    let candidate = openmls_bindings_core::join_external(&candidate_provider, &candidate_identity, group.export_group_info(&alice_provider, &alice, true)?, None)?;
    if candidate.group().has_pending_commit() { candidate.group().merge_pending_commit(&candidate_provider)?; }
    let before = welcome.public_context_fingerprint()?;
    let conn = rusqlite::Connection::open(&path)?;
    let dump = || -> Result<String, Box<dyn std::error::Error>> {
        let mut all = String::new();
        let mut tables = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
        for name in tables.query_map([], |row| row.get::<_,String>(0))? {
            let name = name?;
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{}\" ORDER BY rowid",name.replace('"',"\"\"")))?;
            let columns = stmt.column_count(); let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? { for index in 0..columns { all.push_str(&format!("{:?}",row.get_ref(index)?)); } }
        }
        Ok(all)
    };
    let stored = dump()?;
    assert_eq!(candidate.group().public_context_fingerprint()?, welcome.staged_external_commit_public_context_fingerprint(&original, candidate.commit_bytes())?);
    assert_eq!(stored, dump()?); assert_eq!(before, welcome.public_context_fingerprint()?); assert_eq!(1, welcome.epoch());
    let mut malformed = candidate.commit_bytes(); malformed.push(0);
    assert!(welcome.staged_external_commit_public_context_fingerprint(&original, malformed).is_err());
    assert_eq!(stored, dump()?);
    let reopened = Provider::new_with_path(path)?;
    let retained = Group::load_from_storage(&reopened, "team:staged".into())?;
    assert_eq!(Some(b"before join".to_vec()), retained.process_message(&reopened, history)?.content);
    Ok(())
}

#[test]
fn already_evicted_provider_proves_exact_branch_and_decrypts_only_retained_history() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("evicted.sqlite").to_string_lossy().into_owned();
    let original = Provider::new_with_path(path.clone())?;
    let peer_provider = Provider::new(); let peer = Identity::new(&peer_provider, "peer".into())?;
    let owner = Identity::new(&original, "owner".into())?;
    let founder = Group::create_with_cid(&peer_provider, &peer, "team:evicted".into())?;
    let add = founder.add_members(&peer_provider, &peer, vec![owner.key_package(&original)?])?;
    founder.merge_pending_commit(&peer_provider)?;
    let tree = founder.export_ratchet_tree().to_bytes();
    let old = Group::join_with_welcome(&original, add.welcome.ok_or("missing Welcome")?, Some(founder.export_ratchet_tree()))?;
    old.save_state(&original)?;
    let history = founder.create_message(&peer_provider, &peer, b"retained actual history".to_vec())?;
    let next = Provider::new(); let next_owner = Identity::from_bytes(&next, owner.to_bytes()?)?;
    let candidate = openmls_bindings_core::join_external(&next, &next_owner, founder.export_group_info(&peer_provider, &peer, true)?, None)?;
    if candidate.group().has_pending_commit() { candidate.group().merge_pending_commit(&next)?; }
    old.process_message(&original, candidate.commit_bytes())?; old.save_state(&original)?;
    assert!(!old.is_operational()); assert_eq!(2, old.epoch());
    assert!(old.process_message_deferred(&original, history.clone()).is_err());
    let connection = rusqlite::Connection::open(&path)?;
    let snapshot = || -> Result<String, Box<dyn std::error::Error>> {
        let mut result = String::new();
        let mut tables = connection.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
        for table in tables.query_map([], |row| row.get::<_,String>(0))? {
            let table = table?;
            let mut query = connection.prepare(&format!("SELECT * FROM \"{}\" ORDER BY rowid", table.replace('"', "\"\"")))?;
            let count = query.column_count(); let mut rows = query.query([])?;
            while let Some(row) = rows.next()? { for index in 0..count { result.push_str(&format!("{:?}",row.get_ref(index)?)); } }
        }
        Ok(result)
    };
    let rows_before = snapshot()?;
    assert_eq!(candidate.group().public_context_fingerprint()?, old.evicted_external_commit_public_context_fingerprint(&original, candidate.commit_bytes(), tree.clone(), 2)?);
    assert!(!old.is_operational()); assert_eq!(2, old.epoch());
    let foreign_provider = Provider::new(); let foreign = Identity::new(&foreign_provider, "peer".into())?;
    let foreign_group = Group::create_with_cid(&foreign_provider, &foreign, "team:evicted".into())?;
    assert!(old.evicted_external_commit_public_context_fingerprint(&original, candidate.commit_bytes(), foreign_group.export_ratchet_tree().to_bytes(), 2).is_err());
    assert!(old.evicted_external_commit_public_context_fingerprint(&original, candidate.commit_bytes(), tree.clone(), 3).is_err());
    founder.process_message(&peer_provider, candidate.commit_bytes())?;
    let current = founder.create_message(&peer_provider, &peer, b"new epoch forbidden".to_vec())?;
    assert!(old.process_evicted_epoch_application_deferred(&original, current, tree.clone(), 2).is_err());
    assert!(old.process_evicted_epoch_application_deferred(&original, candidate.commit_bytes(), tree.clone(), 2).is_err());
    assert!(old.process_evicted_epoch_application_deferred(&original, history.clone(), vec![0], 2).is_err());
    assert_eq!(rows_before, snapshot()?);
    assert_eq!(Some(b"retained actual history".to_vec()), old.process_evicted_epoch_application_deferred(&original, history.clone(), tree.clone(), 2)?.content);
    assert!(!old.is_operational()); assert_eq!(2, old.epoch()); old.save_state(&original)?;
    let reopened_provider = Provider::new_with_path(path)?;
    let reopened = Group::load_from_storage(&reopened_provider, "team:evicted".into())?;
    assert!(!reopened.is_operational()); assert!(reopened.process_evicted_epoch_application_deferred(&reopened_provider, history, tree, 2).is_err());
    Ok(())
}
