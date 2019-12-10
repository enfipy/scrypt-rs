#![no_std]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate alloc;

mod errors;
mod params;
mod romix;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
pub use params::*;
pub use errors::*;

pub fn scrypt(
    password: &[u8], salt: &[u8], params: &params::ScryptParams, output: &mut [u8]
) -> Result<(), InvalidOutputLen> {
    // This check required by Scrypt:
    // check output.len() > 0 && output.len() <= (2^32 - 1) * 32
    if !(output.len() > 0 && output.len() / 32 <= 0xffffffff) {
        Err(InvalidOutputLen)?;
    }

    // The checks in the ScryptParams constructor guarantee
    // that the following is safe:
    let n = 1 << params.log_n;
    let r128 = (params.r as usize) * 128;
    let pr128 = (params.p as usize) * r128;
    let nr128 = n * r128;

    let mut b = vec![0u8; pr128];
    pbkdf2::<Hmac<Sha256>>(&password, salt, 1, &mut b);

    let mut v = vec![0u8; nr128];
    let mut t = vec![0u8; r128];

    for chunk in &mut b.chunks_mut(r128) {
        romix::scrypt_ro_mix(chunk, &mut v, &mut t, n);
    }

    pbkdf2::<Hmac<Sha256>>(&password, &b, 1, output);
    Ok(())
}
