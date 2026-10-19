use openmls_wasm::{Group, Identity, Provider};
use sha2::{Digest, Sha256};

#[test]
fn validates_exact_public_head_without_provider_mutation() -> Result<(), String> {
    let provider = Provider::new();
    let identity = Identity::new(&provider, "group-info-validation-user")
        .map_err(|_| "Identity setup failed")?;
    let group = Group::create_with_cid(&provider, &identity, "team:readonly-gi")
        .map_err(|_| "Group setup failed")?;
    let package = identity
        .key_package_typed(&provider)
        .map_err(|e| e.code_name())?;
    let reference = package
        .hash_ref(&provider)
        .map_err(|_| "Reference failed")?;
    let bytes = group
        .export_group_info(&provider, &identity, true)
        .map_err(|_| "Export failed")?;
    let before = Sha256::digest(provider.to_bytes().map_err(|_| "Snapshot failed")?).to_vec();
    for policy in [false, true] {
        let validated =
            Group::validate_group_info_with_policy(&provider, &identity, &bytes, policy)
                .map_err(|e| e.code_name())?;
        assert_eq!(validated.epoch(), group.epoch());
        assert_eq!(validated.group_id(), group.group_id());
        let tree = group.export_ratchet_tree().to_bytes();
        assert_eq!(
            validated.ratchet_tree_sha256(),
            Sha256::digest(tree).to_vec()
        );
        assert_eq!(
            Sha256::digest(provider.to_bytes().map_err(|_| "Snapshot failed")?).to_vec(),
            before
        );
        assert!(identity
            .owns_key_package_ref(&provider, reference.clone())
            .map_err(|_| "Probe failed")?);
    }
    let mut corrupted = bytes.clone();
    if let Some(last) = corrupted.last_mut() {
        *last ^= 1;
    }
    assert!(
        Group::validate_group_info_with_policy(&provider, &identity, &corrupted, false).is_err()
    );
    let mut trailing = bytes;
    trailing.push(0);
    for bad in [Vec::new(), corrupted, trailing, vec![0; 1_048_577]] {
        assert!(Group::validate_group_info_with_policy(&provider, &identity, &bad, false).is_err());
        assert_eq!(
            Sha256::digest(provider.to_bytes().map_err(|_| "Snapshot failed")?).to_vec(),
            before
        );
    }
    Ok(())
}
