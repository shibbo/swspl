use std::io::{self, Read, Seek, SeekFrom};
use lz4_flex::decompress;
use sha2::{Sha256, Digest};

// jumps to a specific offset within a file
// we will always jump from the start of the file
pub fn jump_to_offs<R: Seek + std::io::Read>(reader: &mut R, offset: u64) -> io::Result<()> {
    reader.seek(SeekFrom::Start(offset))?;
    Ok(())
}

// read a specified number of bytes
pub fn read_bytes<R: Read>(reader: &mut R, num: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; num];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

// decompress data using lz4
pub fn decompress_data(bytes: &[u8], compressed_size: usize, decompressed_size: usize) -> io::Result<Vec<u8>> {
    let mut decompressed = vec![0u8; decompressed_size];
    let mut decompressed_data = decompress(bytes, compressed_size).map_err(|e| {
        eprintln!("Decompression failed: {:?}", e);
        io::Error::new(io::ErrorKind::Other, "lz4 decompression failed")
    })?;
    
    Ok(decompressed_data)
}

// check to see if hashes match
pub fn check_hash(data: &[u8], hash: &[u8]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    *hash.as_slice() == *hash
}