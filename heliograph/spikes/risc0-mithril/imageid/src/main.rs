//! Combine a guest user ELF with the v1compat kernel and print the image ID —
//! the same derivation risc0-build v3.0.5 performs in `GuestListEntry::build`.

use risc0_binfmt::ProgramBinary;
use risc0_zkos_v1compat::V1COMPAT_ELF;
use sha2::{Digest, Sha256};

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: imageid <user-elf>"))?;
    let user_elf = std::fs::read(&path)?;
    let binary = ProgramBinary::new(&user_elf, V1COMPAT_ELF);
    let combined = binary.encode();
    let image_id = risc0_binfmt::compute_image_id(&combined)?;
    println!("user_elf: {path}");
    println!("user_elf_sha256: {}", hex::encode(Sha256::digest(&user_elf)));
    println!("combined_sha256: {}", hex::encode(Sha256::digest(&combined)));
    println!("image_id: {image_id}");
    Ok(())
}
