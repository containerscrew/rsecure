use assert_cmd::cargo::cargo_bin_cmd;
use std::fs;
use tempfile::tempdir;

#[test]
fn encrypt_and_decrypt_single_file_roundtrip() {
    let dir = tempdir().unwrap();

    let key_path = dir.path().join("key.bin");
    let file_path = dir.path().join("secret.txt");
    let enc_path = dir.path().join("secret.txt.enc");

    fs::write(&file_path, b"hola mundo secreto").unwrap();

    // 1️⃣ create key
    cargo_bin_cmd!("rsecure")
        .args(["create-key", "-o", key_path.to_str().unwrap()])
        .assert()
        .success();

    assert!(key_path.exists());

    // 2️⃣ encrypt file
    cargo_bin_cmd!("rsecure")
        .args([
            "encrypt",
            "-p",
            key_path.to_str().unwrap(),
            "-s",
            file_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(enc_path.exists());

    // 3️⃣ decrypt file
    cargo_bin_cmd!("rsecure")
        .args([
            "decrypt",
            "-p",
            key_path.to_str().unwrap(),
            "-s",
            enc_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // 4️⃣ verify content restored
    let decrypted = fs::read(&file_path).unwrap();
    assert_eq!(decrypted, b"hola mundo secreto");
}
