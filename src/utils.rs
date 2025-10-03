use std::path::Path;

/// Returns true if the path is a file
pub fn is_file(path: &str) -> bool {
    Path::new(path).is_file()
}

/// Returns true if the path is a directory
pub fn is_dir(path: &str) -> bool {
    Path::new(path).is_dir()
}