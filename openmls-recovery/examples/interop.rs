use openmls_recovery::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::io::Read;
fn main() {
    let p=OpenMlsRustCrypto::default();
    if std::env::args().nth(1).as_deref()==Some("verify") {
        let mut input=String::new();std::io::stdin().read_to_string(&mut input).unwrap();
        let v:serde_json::Value=serde_json::from_str(&input).unwrap();
        let key:RecoveryKeypair=serde_json::from_value(v["keys"].clone()).unwrap();
        let vault:WrappedRecoveryKey=serde_json::from_value(v["vault"].clone()).unwrap();
        assert_eq!(unwrap_recovery_private_key(&p,"12345678",&vault).unwrap(),key.private_key);
        let blob:EncryptedArchiveBlob=serde_json::from_value(v["blob"].clone()).unwrap();
        let wrap:HpkeWrappedArchiveDataKey=serde_json::from_value(v["wrap"].clone()).unwrap();
        let adk=unwrap_archive_data_key(&p,&key.private_key,&wrap).unwrap();
        assert_eq!(decrypt_archive_blob(&p,&adk,&blob.ciphertext,&blob.nonce,&blob.aead_aad).unwrap(),b"cross-platform-recovery");
        println!("web_to_native_passed");return;
    }
    let keys=generate_recovery_keypair(&p).unwrap();
    let vault=wrap_recovery_private_key(&p,"12345678",&keys.private_key,&keys.public_key,&keys.key_id,3,600_000).unwrap();
    let aad=ArchiveBlobAad::for_generation("messaging:interop".into(),3,7,"account_owned".into(),"fixture-blob".into(),"fixture-snapshot".into());
    let info=ArchiveKeyWrapInfo::for_generation("messaging:interop".into(),3,7,"account_owned".into(),"fixture-blob".into(),"fixture-snapshot".into(),keys.key_id.clone());
    let blob=encrypt_archive_blob(&p,b"cross-platform-recovery",&aad).unwrap();
    let wrap=wrap_archive_data_key(&p,&blob.adk,&keys.public_key,&info).unwrap();
    println!("{}",serde_json::json!({"keys":keys,"vault":vault,"blob":blob,"wrap":wrap}));
}
