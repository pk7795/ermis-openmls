use openmls_bindings_core::{Group, Identity, Provider};

#[test]
fn ownership_requires_private_bundle_and_current_signer() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    let path = root
        .path()
        .join("provider.sqlite")
        .to_string_lossy()
        .into_owned();
    let provider = Provider::new_with_path(path.clone())?;
    let identity = Identity::new(&provider, "bob".into())?;
    let identity_bytes = identity.to_bytes()?;
    let kp = identity.key_package(&provider)?;
    let reference = kp.hash_ref(&provider)?;
    assert!(identity.owns_key_package_ref(&provider, reference.clone())?);
    assert!(!identity.owns_key_package_ref(&provider, vec![0; 32])?);
    assert!(identity
        .owns_key_package_ref(&provider, vec![0; 31])
        .is_err());
    // Same account with a different signing identity cannot claim this bundle.
    let replacement = Identity::new(&provider, "bob".into())?;
    assert!(!replacement.owns_key_package_ref(&provider, reference.clone())?);
    drop(replacement);
    drop(identity);
    drop(provider);
    let provider = Provider::new_with_path(path.clone())?;
    let identity = Identity::from_bytes(&provider, identity_bytes.clone())?;
    assert!(identity.owns_key_package_ref(&provider, reference.clone())?);
    // A real Welcome consumes only the selected private bundle.
    let spare = identity.key_package(&provider)?.hash_ref(&provider)?;
    let inviter_provider = Provider::new();
    let inviter = Identity::new(&inviter_provider, "alice".into())?;
    let group = Group::create_with_cid(&inviter_provider, &inviter, "team:ownership".into())?;
    let added = group.add_members(&inviter_provider, &inviter, vec![kp])?;
    group.merge_pending_commit(&inviter_provider)?;
    let welcome = added.welcome.ok_or("missing Welcome")?;
    let joined = Group::join_with_welcome(&provider, welcome, Some(group.export_ratchet_tree()))?;
    assert!(!identity.owns_key_package_ref(&provider, reference.clone())?);
    assert!(identity.owns_key_package_ref(&provider, spare.clone())?);
    drop(joined);
    drop(identity);
    drop(provider);
    let provider = Provider::new_with_path(path)?;
    let identity = Identity::from_bytes(&provider, identity_bytes)?;
    assert!(!identity.owns_key_package_ref(&provider, reference)?);
    assert!(identity.owns_key_package_ref(&provider, spare)?);
    Ok(())
}

#[test]
fn corrupt_or_mismatched_bundle_is_uncertain_even_with_foreign_signer(
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("ownership.sqlite");
    let provider = Provider::new_with_path(path.to_string_lossy().into())?;
    let identity = Identity::new(&provider, "bob".into())?;
    let kp = identity.key_package(&provider)?;
    let reference = kp.hash_ref(&provider)?;
    let foreign = Identity::new(&provider, "bob".into())?;
    let foreign_kp = foreign.key_package(&provider)?;
    let foreign_reference = foreign_kp.hash_ref(&provider)?;
    let conn = rusqlite::Connection::open(path)?;
    let encoded = |reference| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use tls_codec::Serialize;
        let reference = openmls::prelude::KeyPackageRef::tls_deserialize_exact(
            &tls_codec::VLBytes::new(reference).tls_serialize_detached()?,
        )?;
        Ok(serde_json::to_vec(&reference)?)
    };
    use tls_codec::Deserialize;
    let reference_json = encoded(reference.clone())?;
    let foreign_json = encoded(foreign_reference)?;
    let foreign_bundle: Vec<u8> = conn.query_row(
        "SELECT key_package FROM openmls_key_packages WHERE key_package_ref = ?1",
        [&foreign_json],
        |row| row.get(0),
    )?;
    conn.execute(
        "UPDATE openmls_key_packages SET key_package = ?1 WHERE key_package_ref = ?2",
        rusqlite::params![foreign_bundle, reference_json],
    )?;
    assert!(identity
        .owns_key_package_ref(&provider, reference.clone())
        .is_err());
    assert!(foreign
        .owns_key_package_ref(&provider, reference.clone())
        .is_err());
    conn.execute(
        "UPDATE openmls_key_packages SET key_package = ?1 WHERE key_package_ref = ?2",
        rusqlite::params![b"broken".as_slice(), reference_json],
    )?;
    assert!(identity
        .owns_key_package_ref(&provider, reference.clone())
        .is_err());
    conn.execute_batch("DROP TABLE openmls_key_packages")?;
    assert!(identity.owns_key_package_ref(&provider, reference).is_err());
    Ok(())
}
