use std::io::Read;
use std::path::Path;

/// Returns true if the path is a file
pub fn is_file(path: &str) -> bool {
    Path::new(path).is_file()
}

/// Returns true if the path is a directory
pub fn is_dir(path: &str) -> bool {
    Path::new(path).is_dir()
}

/// Read from `reader` until `buf` is full or the stream ends, looping over
/// short reads. Returns the number of bytes actually read.
///
/// `std::io::Read::read` is permitted to return fewer bytes than requested
/// without being at end-of-file. The STREAM chunking logic relies on "a full
/// buffer means an intermediate chunk, a partial buffer means the final
/// chunk", so a naive single `read` could misclassify a short read as the
/// terminal chunk. Draining short reads here guarantees a return value less
/// than `buf.len()` signals genuine end-of-file.
pub fn fill_buffer<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}
