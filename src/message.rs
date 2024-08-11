use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::ed25519::SignatureBytes;
use zerocopy::{big_endian, AsBytes, FromBytes, FromZeroes, Unaligned};

use crate::{
    block::{BlockKey, Timestamp},
    bloom::{BloomFilter, PeerBloomFilter},
    Peer,
};

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(C)]
pub struct MessageHeader {
    message_size: big_endian::U16,
    message_type: big_endian::U16,
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(C)]
pub struct Flags(u8);

impl Flags {
    fn get_demultiplex(&self) -> bool {
        (self.0 >> 0) & 1 == 1
    }
    fn get_record_route(&self) -> bool {
        (self.0 >> 1) & 1 == 1
    }
    fn get_find_approximate(&self) -> bool {
        (self.0 >> 2) & 1 == 1
    }
    fn get_truncated(&self) -> bool {
        (self.0 >> 3) & 1 == 1
    }
}

// https://datatracker.ietf.org/doc/html/draft-schanzen-r5n-05#section-7.2
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(C)]
pub struct HelloMessage {
    header: MessageHeader,
    /// Must be 0
    version: big_endian::U16,
    num_addresses: big_endian::U16,
    signature: SignatureBytes,
    expiration: Timestamp,
}

// https://datatracker.ietf.org/doc/html/draft-schanzen-r5n-05#section-7.3
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(C)]
pub struct PutMessageHeader {
    header: MessageHeader,
    block_type: big_endian::U32,
    version: u8,
    flags: Flags,
    hop_count: big_endian::U16,
    replication_level: big_endian::U16,
    path_len: big_endian::U16,
    expiration: Timestamp,
    peer_bloom_filter: PeerBloomFilter,
    block_key: BlockKey,
}

pub struct PutMessage<'a> {
    header: &'a PutMessageHeader,
    truncated_origin: Option<&'a [u8; 32]>,
    put_path: &'a [u8],
    last_hop_signature: Option<&'a SignatureBytes>,
    block: &'a [u8],
}

impl<'a> PutMessage<'a> {
    pub fn parse(mut b: &'a [u8]) -> Option<Self> {
        let header = PutMessageHeader::ref_from_prefix(b)?;
        assert_eq!(header.header.message_type.get(), 146);

        b = b.get(size_of_val(header)..header.header.message_size.get() as usize)?;

        let truncated = if header.flags.get_truncated() {
            let t = <[u8; 32]>::ref_from_prefix(b)?;
            b = b.get(size_of_val(t)..)?;
            Some(t)
        } else {
            None
        };
        let (path, mut b) = b.split_at_checked(header.path_len.get() as usize)?;
        let signature = if header.flags.get_record_route() {
            let s = SignatureBytes::ref_from_prefix(b)?;
            b = b.get(size_of_val(s)..)?;
            Some(s)
        } else {
            None
        };

        Some(Self {
            header,
            truncated_origin: truncated,
            put_path: path,
            last_hop_signature: signature,
            block: b,
        })
    }
}

// https://datatracker.ietf.org/doc/html/draft-schanzen-r5n-05#section-7.4
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(C)]
pub struct GetMessageHeader {
    header: MessageHeader,
    block_type: big_endian::U32,
    version: u8,
    flags: Flags,
    hop_count: big_endian::U16,
    replication_level: big_endian::U16,
    result_filter_size: big_endian::U16,
    peer_bloom_filter: PeerBloomFilter,
    query_hash: [u8; 64],
}

// https://datatracker.ietf.org/doc/html/draft-schanzen-r5n-05#section-7.4
pub struct ResultMessage {}
