use openmls_bindings_core::{Group, Identity, Provider};

#[test]
fn explicit_group_ids_keep_same_cid_generations_isolated_across_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("generation-provider.sqlite");
    let database_path = database_path.to_string_lossy().into_owned();
    let legacy_group_id = b"team:same-cid".to_vec();
    let next_group_id = vec![0xff, 1, 0, 42, 7, 99];

    {
        let provider = Provider::new_with_path(database_path.clone())?;
        let founder = Identity::new(&provider, "alice".to_owned())?;
        let legacy = Group::create_with_cid(&provider, &founder, "team:same-cid".to_owned())?;
        let next = Group::create_with_group_id(&provider, &founder, next_group_id.clone())?;
        legacy.save_state(&provider)?;
        next.save_state(&provider)?;
        assert_eq!(legacy.group_id(), legacy_group_id);
        assert_eq!(next.group_id(), next_group_id);
    }

    let restarted = Provider::new_with_path(database_path)?;
    let legacy = Group::load_from_storage(&restarted, "team:same-cid".to_owned())?;
    let next = Group::load_from_storage_with_group_id(&restarted, next_group_id.clone())?;
    assert_eq!(legacy.group_id(), legacy_group_id);
    assert_eq!(next.group_id(), next_group_id);
    assert_eq!(legacy.epoch(), 0);
    assert_eq!(next.epoch(), 0);
    Ok(())
}

#[test]
fn explicit_group_id_rejects_empty_and_oversized_values() -> Result<(), Box<dyn std::error::Error>>
{
    let provider = Provider::new();
    let founder = Identity::new(&provider, "alice".to_owned())?;
    assert!(Group::create_with_group_id(&provider, &founder, Vec::new()).is_err());
    assert!(Group::create_with_group_id(&provider, &founder, vec![7; 256]).is_err());
    assert!(Group::load_from_storage_with_group_id(&provider, Vec::new()).is_err());
    Ok(())
}
