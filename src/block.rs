use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{ed25519::SignatureBytes, Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use zerocopy::{big_endian, AsBytes, FromBytes, FromZeroes, Unaligned};

use crate::Peer;

trait BlockOperation {
    /// is used to evaluate the request for a block as part of GetMessage processing. Here, the block payload is unkown, but if possible the XQuery and Key SHOULD be verified
    fn validate_block_query(key: &BlockKey, x_query: &[u8]) -> bool;
    /// is used to synthesize the block key from the block payload as part of PutMessage and ResultMessage processing. The special return value of NONE implies that this block type does not permit deriving the key from the block. A Key may be returned for a block that is ill-formed
    fn derive_block_key(&self) -> Option<BlockKey>;
    /// is used to evaluate a block payload as part of PutMessage and ResultMessage processing
    fn validate_block_store_request(&self) -> bool;

    // fn setup_result_filter();
    // fn filter_result();
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(C)]
pub struct BlockKey([u8; 64]);

/// https://datatracker.ietf.org/doc/html/draft-schanzen-r5n-05#section-8.2
pub struct HelloBlock<'a> {
    header: &'a HelloBlockHeader,
    addrs: Addrs<'a>,
}

impl BlockOperation for HelloBlock<'_> {
    fn validate_block_query(_key: &BlockKey, x_query: &[u8]) -> bool {
        x_query.is_empty()
    }

    fn derive_block_key(&self) -> Option<BlockKey> {
        let peer: Peer = self.header.peer_public_key.into();
        Some(BlockKey(peer.id().0))
    }

    fn validate_block_store_request(&self) -> bool {
        let Some(pk): Option<VerifyingKey> = self.header.peer_public_key.try_into().ok() else {
            return false;
        };

        let sig = HelloBlockSignaturePayload {
            size: big_endian::U32::new(80),
            purpose: big_endian::U32::new(7),
            expiration: self.header.expiration,
            hash_addrs: Sha512::digest(self.addrs.0).into(),
        };
        let expected_sig = Signature::from_bytes(&self.header.signature);

        pk.verify(sig.as_bytes(), &expected_sig).is_ok()
    }
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(C)]
pub struct HelloBlockHeader {
    peer_public_key: PublicKey,
    signature: SignatureBytes,
    expiration: Timestamp,
}

impl<'a> HelloBlock<'a> {
    pub fn parse(mut b: &'a [u8]) -> Option<Self> {
        let header = HelloBlockHeader::ref_from_prefix(b)?;
        b = b.get(size_of_val(header)..)?;

        let sig = HelloBlockSignaturePayload {
            size: big_endian::U32::new(80),
            purpose: big_endian::U32::new(7),
            expiration: header.expiration,
            hash_addrs: Sha512::digest(b).into(),
        };
        let pk: VerifyingKey = header.peer_public_key.try_into().ok()?;
        let expected_sig = Signature::from_bytes(&header.signature);
        pk.verify(sig.as_bytes(), &expected_sig).ok()?;

        let s = std::str::from_utf8(b).ok()?;
        Some(Self {
            header,
            addrs: Addrs(s),
        })
    }
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
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

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned, Clone, Copy)]
#[repr(transparent)]
pub struct Timestamp(big_endian::U64);

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned, Clone, Copy)]
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
