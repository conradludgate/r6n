use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{ed25519::SignatureBytes, Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use zerocopy::{big_endian, AsBytes, FromBytes, FromZeroes, Unaligned};

use crate::{bloom::BloomFilter, xor, Peer};

pub enum FilterResult {
    /// Block is a valid result, and there may be more.
    More,
    /// The given Block is the last possible valid result.
    Last,
    /// Block is a valid result, but considered to be a duplicate
    /// (was filtered by the RF) and SHOULD NOT be returned to the
    /// previous hop. Peers that do not understand the block type MAY
    /// return such duplicate results anyway and implementations must
    /// take this into account.
    Duplicate,
    /// Block does not satisfy the constraints imposed by the XQuery.
    /// The result SHOULD NOT be returned to the previous hop. Peers
    /// that do not understand the block type MAY return such irrelevant
    /// results anyway and implementations must take this into account.
    Irrelevant,
}

trait BlockOperation {
    /// is used to evaluate the request for a block as part of GetMessage processing. Here, the block payload is unkown, but if possible the XQuery and Key SHOULD be verified
    fn validate_block_query(key: &BlockKey, x_query: &[u8]) -> bool;
    /// is used to synthesize the block key from the block payload as part of PutMessage and ResultMessage processing. The special return value of NONE implies that this block type does not permit deriving the key from the block. A Key may be returned for a block that is ill-formed
    fn derive_block_key(&self) -> Option<BlockKey>;
    /// is used to evaluate a block payload as part of PutMessage and ResultMessage processing
    fn validate_block_store_request(&self) -> bool;

    type Mutator;
    fn setup_result_filter(&self, filter_size: u32, mutator: Self::Mutator) -> Vec<u8>;
    fn filter_result(&self, key: &BlockKey, rf: &mut [u8], x_query: &[u8]) -> FilterResult;
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

    type Mutator = u32;
    fn setup_result_filter(&self, filter_size: u32, mutator: Self::Mutator) -> Vec<u8> {
        const MAX_BYTES: u32 = 1 << 15;
        let e = filter_size.next_power_of_two();
        let b = e * 16 / 4;

        let mut result_filter = vec![0u8; b as usize + 4];
        result_filter[..4].copy_from_slice(&mutator.to_be_bytes()[..]);
        result_filter
    }

    fn filter_result(&self, _key: &BlockKey, rf: &mut [u8], _x_query: &[u8]) -> FilterResult {
        let Some(mutator) = rf.get(..4) else {
            return FilterResult::Irrelevant;
        };
        let mutator: [u8; 4] = mutator.try_into().unwrap();

        let Some(bloom) = BloomFilter::from(&mut rf[4..]) else {
            return FilterResult::Irrelevant;
        };

        // let mutator = u32::from_be_bytes(mutator);
        let mutator = Sha512::digest(mutator).into();
        let hash_addrs = Sha512::digest(self.addrs.0.as_bytes()).into();
        let e = xor(&mutator, &hash_addrs);

        if bloom.test(&e) {
            FilterResult::Duplicate
        } else {
            FilterResult::More
        }
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
