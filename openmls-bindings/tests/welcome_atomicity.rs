use openmls_bindings_core::{Group, Identity, Provider};
use rusqlite::Connection;

fn invitation(
    provider: &Provider,
) -> Result<(Identity, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let bob = Identity::new(provider, "bob".into())?;
    let kp = bob.key_package(provider)?;
    let reference = kp.hash_ref(provider)?;
    let sender_provider = Provider::new();
    let sender = Identity::new(&sender_provider, "alice".into())?;
    let group = Group::create_with_cid(&sender_provider, &sender, "team:atomic".into())?;
    let result = group.add_members(&sender_provider, &sender, vec![kp])?;
    Ok((bob, reference, result.welcome.ok_or("missing Welcome")?))
}

#[test]
fn welcome_write_faults_restore_private_bundle_and_all_group_rows(
) -> Result<(), Box<dyn std::error::Error>> {
    // Each persisted Welcome write is exercised through SQLite, after preceding
    // writes have succeeded. This proves rollback, rather than mirroring control flow.
    let writes = [
        ("openmls_key_packages", "DELETE", "1"),
        ("openmls_epoch_keys_pairs", "INSERT", "1"),
        (
            "openmls_group_data",
            "INSERT",
            "NEW.data_type = 'join_group_config'",
        ),
        ("openmls_group_data", "INSERT", "NEW.data_type = 'tree'"),
        (
            "openmls_group_data",
            "INSERT",
            "NEW.data_type = 'interim_transcript_hash'",
        ),
        ("openmls_group_data", "INSERT", "NEW.data_type = 'context'"),
        (
            "openmls_group_data",
            "INSERT",
            "NEW.data_type = 'confirmation_tag'",
        ),
        (
            "openmls_group_data",
            "INSERT",
            "NEW.data_type = 'group_state'",
        ),
        (
            "openmls_group_data",
            "INSERT",
            "NEW.data_type = 'message_secrets'",
        ),
        (
            "openmls_group_data",
            "INSERT",
            "NEW.data_type = 'resumption_psk_store'",
        ),
        (
            "openmls_group_data",
            "INSERT",
            "NEW.data_type = 'own_leaf_index'",
        ),
        (
            "openmls_group_data",
            "INSERT",
            "NEW.data_type = 'group_epoch_secrets'",
        ),
    ];
    for (table, operation, predicate) in writes {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("provider.sqlite");
        let provider = Provider::new_with_path(path.to_string_lossy().into())?;
        let (identity, reference, welcome) = invitation(&provider)?;
        let identity_bytes = identity.to_bytes()?;
        let conn = Connection::open(&path)?;
        conn.execute_batch(&format!(
            "CREATE TRIGGER injected_failure BEFORE {operation} ON {table} WHEN {predicate}
             BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;"
        ))?;
        assert!(
            Group::join_with_welcome(&provider, welcome.clone(), None).is_err(),
            "{table} {predicate}"
        );
        assert!(
            identity.owns_key_package_ref(&provider, reference.clone())?,
            "{table} {predicate}"
        );
        for group_table in [
            "openmls_group_data",
            "openmls_epoch_keys_pairs",
            "openmls_proposals",
            "openmls_own_leaf_nodes",
        ] {
            let count: i64 =
                conn.query_row(&format!("SELECT COUNT(*) FROM {group_table}"), [], |row| {
                    row.get(0)
                })?;
            assert_eq!(
                count, 0,
                "partial write left in {group_table} after {predicate}"
            );
        }
        conn.execute_batch("DROP TRIGGER injected_failure")?;
        drop(identity);
        drop(provider);
        let provider = Provider::new_with_path(path.to_string_lossy().into())?;
        let identity = Identity::from_bytes(&provider, identity_bytes)?;
        assert!(identity.owns_key_package_ref(&provider, reference.clone())?);
        Group::join_with_welcome(&provider, welcome.clone(), None)?;
        assert!(!identity.owns_key_package_ref(&provider, reference)?);
        assert_eq!(provider.group_count()?, 1);
        // Success never restores a consumed single-use package.
        assert!(Group::join_with_welcome(&provider, welcome, None).is_err());
    }
    Ok(())
}

#[test]
fn corrupt_welcome_and_trailing_bytes_do_not_consume_private_package(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider::new();
    let (identity, reference, welcome) = invitation(&provider)?;
    let mut corrupt = welcome.clone();
    let last = corrupt.last_mut().ok_or("empty Welcome")?;
    *last ^= 1;
    assert!(Group::join_with_welcome(&provider, corrupt, None).is_err());
    assert!(identity.owns_key_package_ref(&provider, reference.clone())?);
    let mut trailing = welcome.clone();
    trailing.push(0);
    assert!(Group::join_with_welcome(&provider, trailing, None).is_err());
    assert!(identity.owns_key_package_ref(&provider, reference)?);
    assert_eq!(provider.group_count()?, 0);
    Group::join_with_welcome(&provider, welcome, None)?;
    Ok(())
}
