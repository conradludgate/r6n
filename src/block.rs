use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::ed25519::SignatureBytes;
use zerocopy::{big_endian, AsBytes, FromBytes, FromZeroes};

use crate::Peer;

// https://datatracker.ietf.org/doc/html/draft-schanzen-r5n-05#section-8.2
#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
pub struct HelloBlockHeader {
    peer_public_key: PublicKey,
    signature: SignatureBytes,
    expiration: Timestamp,
}

#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
pub struct HelloBlockSignaturePayload {
    size: big_endian::U32,
    purpose: big_endian::U32,
    expiration: Timestamp,
    hash_addrs: [u8; 64],
}

pub struct Addrs<'a>(&'a str);

impl<'a> Iterator for Addrs<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let (a, b) = self.0.split_once('\0')?;
        self.0 = b;
        Some(a)
    }
}

#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(transparent)]
pub struct Timestamp(big_endian::U64);

#[derive(FromZeroes, FromBytes, AsBytes)]
#[repr(transparent)]
pub struct PublicKey([u8; 32]);

impl From<PublicKey> for CompressedEdwardsY {
    fn from(value: PublicKey) -> Self {
        CompressedEdwardsY(value.0)
    }
}

impl From<PublicKey> for Peer {
    fn from(value: PublicKey) -> Self {
        Peer(value.into())
    }
}

impl TryFrom<PublicKey> for ed25519_dalek::VerifyingKey {
    type Error = ed25519_dalek::SignatureError;
    fn try_from(value: PublicKey) -> Result<Self, ed25519_dalek::SignatureError> {
        ed25519_dalek::VerifyingKey::from_bytes(&value.0)
    }
}
