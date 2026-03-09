use std::{
    fs::File,
    io::{Read, Write},
};

pub fn write_to_file(file_path: &str, contents: &[&[u8]]) -> anyhow::Result<()> {
    let mut file = File::create(file_path)?;
    for content in contents {
        file.write_all(content)?;
    }
    Ok(())
}

pub fn open_private_key(file_path: &str) -> anyhow::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut key_bytes = vec![0u8; 32]; // AES-256 key size
    file.read_exact(&mut key_bytes)?;
    Ok(key_bytes)
}
