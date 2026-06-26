use aes_gcm::aead::stream::EncryptorBE32;
use aes_gcm::{Aes256Gcm, KeyInit};
use assert_cmd::cargo::cargo_bin_cmd;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use tempfile::tempdir;

#[test]
fn encrypt_and_decrypt_single_file_roundtrip() {
    let dir = tempdir().unwrap();

    let key_path = dir.path().join("key.bin");
    let file_path = dir.path().join("secret.txt");
    let enc_path = dir.path().join("secret.txt.enc");

    fs::write(&file_path, b"hola mundo secreto").unwrap();

    cargo_bin_cmd!("rsecure")
        .args(["create-key", "-o", key_path.to_str().unwrap()])
        .assert()
        .success();

    assert!(key_path.exists());

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

    let decrypted = fs::read(&file_path).unwrap();
    assert_eq!(decrypted, b"hola mundo secreto");
}

#[test]
fn encrypt_decrypt_roundtrip_multi_chunk() {
    let dir = tempdir().unwrap();

    let key_path = dir.path().join("key.bin");
    let file_path = dir.path().join("big.bin");
    let enc_path = dir.path().join("big.bin.enc");

    // 320 KiB: spans 3 STREAM chunks (CHUNK_SIZE = 128 KiB) so we exercise both
    // encrypt_next() and encrypt_last() paths under a single nonce salt.
    let mut data = vec![0u8; 320 * 1024];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    fs::write(&file_path, &data).unwrap();

    cargo_bin_cmd!("rsecure")
        .args(["create-key", "-o", key_path.to_str().unwrap()])
        .assert()
        .success();

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

    let decrypted = fs::read(&file_path).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn decrypts_legacy_v1_aes_gcm_file() {
    // Files produced by rsecure <= 0.5.0 had no magic header: just 7 random
    // nonce bytes followed by AES-256-GCM STREAM ciphertext. Construct one
    // here and verify the current binary still decrypts it.
    let dir = tempdir().unwrap();

    let key_path = dir.path().join("key.bin");
    let enc_path = dir.path().join("oldfile.txt.enc");
    let dest_path = dir.path().join("oldfile.txt");

    let key_bytes = [0x42u8; 32];
    fs::write(&key_path, key_bytes).unwrap();

    let payload = b"plaintext encrypted with rsecure 0.5.0 legacy format" as &[u8];

    // Fixed nonce that does not collide with the v2 magic "RSEC".
    let nonce: [u8; 7] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00];

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let encryptor = EncryptorBE32::from_aead(cipher, &nonce.into());
    let ciphertext = encryptor.encrypt_last(payload).unwrap();

    let mut f = fs::File::create(&enc_path).unwrap();
    f.write_all(&nonce).unwrap();
    f.write_all(&ciphertext).unwrap();
    drop(f);

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

    let decrypted = fs::read(&dest_path).unwrap();
    assert_eq!(decrypted.as_slice(), payload);
}

#[test]
fn exclude_dir_matches_components_not_substrings() {
    // Old behavior: -e .git used path.contains(".git") and would also exclude
    // files like forgit.txt or anything inside .github/. New behavior matches
    // single path components only.
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("key.bin");
    let root = dir.path().join("tree");

    // Layout:
    //   tree/.git/config         — excluded (component matches)
    //   tree/.github/workflows.yml — NOT excluded (component is ".github")
    //   tree/forgit.txt          — NOT excluded (component is "forgit.txt")
    //   tree/keep/file.txt       — NOT excluded
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::create_dir_all(root.join(".github")).unwrap();
    fs::create_dir_all(root.join("keep")).unwrap();
    fs::write(root.join(".git/config"), b"should be excluded").unwrap();
    fs::write(root.join(".github/workflows.yml"), b"should be encrypted").unwrap();
    fs::write(root.join("forgit.txt"), b"should be encrypted").unwrap();
    fs::write(root.join("keep/file.txt"), b"should be encrypted").unwrap();

    cargo_bin_cmd!("rsecure")
        .args(["create-key", "-o", key_path.to_str().unwrap()])
        .assert()
        .success();

    cargo_bin_cmd!("rsecure")
        .args([
            "encrypt",
            "-p",
            key_path.to_str().unwrap(),
            "-s",
            root.to_str().unwrap(),
            "-e",
            ".git",
        ])
        .assert()
        .success();

    // Excluded → no .enc produced; plaintext untouched.
    assert!(root.join(".git/config").exists());
    assert!(!root.join(".git/config.enc").exists());

    // Not excluded → .enc produced.
    assert!(root.join(".github/workflows.yml.enc").exists());
    assert!(root.join("forgit.txt.enc").exists());
    assert!(root.join("keep/file.txt.enc").exists());
}

#[test]
fn decrypt_fails_when_v2_header_is_tampered() {
    // The v2 header (magic + version + chunk_size + hkdf_salt) is bound to every
    // chunk's GCM tag via AAD. Flipping a single bit in the header — here, in
    // the chunk_size field at offset 5 — must make decryption fail with an
    // auth error and a non-zero exit status.
    let dir = tempdir().unwrap();

    let key_path = dir.path().join("key.bin");
    let file_path = dir.path().join("secret.txt");
    let enc_path = dir.path().join("secret.txt.enc");

    let payload: &[u8] = b"contenido legitimo que no debe descifrarse si alguien toca la cabecera";
    fs::write(&file_path, payload).unwrap();

    cargo_bin_cmd!("rsecure")
        .args(["create-key", "-o", key_path.to_str().unwrap()])
        .assert()
        .success();

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

    // Remove the plaintext so we can detect any unauthorized recovery.
    fs::remove_file(&file_path).unwrap();

    // Flip one bit inside the chunk_size field (byte offset 5).
    let mut enc_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&enc_path)
        .unwrap();
    enc_file.seek(SeekFrom::Start(5)).unwrap();
    let mut byte = [0u8; 1];
    enc_file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x01;
    enc_file.seek(SeekFrom::Start(5)).unwrap();
    enc_file.write_all(&byte).unwrap();
    drop(enc_file);

    cargo_bin_cmd!("rsecure")
        .args([
            "decrypt",
            "-p",
            key_path.to_str().unwrap(),
            "-s",
            enc_path.to_str().unwrap(),
        ])
        .assert()
        .failure();

    // Atomic decrypt writes to <source>.dec.tmp and only renames on success,
    // so a failed auth check must not leave any plaintext at the final path.
    assert!(
        !file_path.exists(),
        "atomic decrypt must not leave partial plaintext after auth failure"
    );
    // The encrypted source must be preserved on failure (we only remove it on
    // a clean rename).
    assert!(enc_path.exists(), "source .enc must be preserved on failure");
}
