//! Fixed-offset big-endian reads/writes over the single journal buffer. Every
//! offset comes from `consts`; the R1 length gate pins the buffer to the claim
//! type's exact `LEN_*` before any view exists, so accesses here are in-bounds.
//! An out-of-bounds panic is a codec defect surfacing as a proving failure,
//! never a wrong verdict (HANDOFF §5).

pub(crate) fn be_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

pub(crate) fn be_u32(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[off..off + 4]);
    u32::from_be_bytes(b)
}

pub(crate) fn be_u64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_be_bytes(b)
}

pub(crate) fn arr32(buf: &[u8], off: usize) -> &[u8; 32] {
    match buf[off..off + 32].try_into() {
        Ok(a) => a,
        // The slice above is exactly 32 bytes, so the conversion cannot fail.
        Err(_) => unreachable!("arr32 slice is 32 bytes"),
    }
}

pub(crate) fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

pub(crate) fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_arr32(buf: &mut [u8], off: usize, v: &[u8; 32]) {
    buf[off..off + 32].copy_from_slice(v);
}
