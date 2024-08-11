use zerocopy::{big_endian, AsBytes, FromBytes, FromZeroes, Unaligned};

#[derive(FromBytes, FromZeroes, AsBytes, Unaligned)]
#[repr(C)]
pub struct PeerBloomFilter {
    bits: [u8; 128],
}

impl Default for PeerBloomFilter {
    fn default() -> Self {
        Self { bits: [0; 128] }
    }
}

impl PeerBloomFilter {
    fn get_ref(&self) -> BloomFilter<&[u8; 128]> {
        BloomFilter {
            byte_mask: 127,
            bytes: &self.bits,
        }
    }
    fn get_mut(&mut self) -> BloomFilter<&mut [u8; 128]> {
        BloomFilter {
            byte_mask: 127,
            bytes: &mut self.bits,
        }
    }
}

pub struct BloomFilter<B> {
    byte_mask: u32,
    bytes: B,
}

impl BloomFilter<Vec<u8>> {
    pub fn new(bits: u32) -> Option<Self> {
        if !bits.is_power_of_two() || bits < 8 {
            return None;
        }
        let bytes = bits / 8;
        let byte_mask = bytes - 1;
        Some(Self {
            byte_mask,
            bytes: vec![0; bytes as usize],
        })
    }
}

impl<B: AsRef<[u8]>> BloomFilter<B> {
    /// return true if id is in the filter
    pub fn test(&self, key: &[u8; 64]) -> bool {
        bf_test_inner(self.bytes.as_ref(), self.byte_mask, key)
    }
}

impl<B: AsMut<[u8]>> BloomFilter<B> {
    pub fn insert(&mut self, key: &[u8; 64]) {
        bf_insert_inner(self.bytes.as_mut(), self.byte_mask, key)
    }
}

fn bf_test_inner(bytes: &[u8], mask: u32, key: &[u8; 64]) -> bool {
    let keys = Keys::ref_from(key).unwrap();
    let mask = mask as usize;

    let mut out = true;
    for k in keys.0 {
        let k = k.get();
        let bit = k & 0x7;
        let byte = (k >> 3) as usize;

        assert!(mask < bytes.len());

        let byte = byte & mask;
        // byte <= mask, therefore byte < bytes.len()
        if bytes[byte] >> bit & 1 == 0 {
            out &= false;
        }
    }

    out
}

fn bf_insert_inner(bytes: &mut [u8], mask: u32, key: &[u8; 64]) {
    let keys = Keys::ref_from(key).unwrap();
    let mask = mask as usize;

    for k in keys.0 {
        let k = k.get();
        let bit = k & 0x7;
        let byte = (k >> 3) as usize;

        assert!(mask < bytes.len());

        let byte = byte & mask;
        // byte <= mask, therefore byte < bytes.len()
        bytes[byte] |= 1 << bit;
    }
}

#[derive(FromBytes, FromZeroes)]
struct Keys([big_endian::U32; 16]);

#[cfg(test)]
mod tests {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    use crate::{
        bloom::{BloomFilter, PeerBloomFilter},
        Peer,
    };

    #[test]
    fn happy() {
        let mut bloom = PeerBloomFilter::default();
        let mut bloom = bloom.get_mut();

        let peer1 = Peer(CompressedEdwardsY([1; 32])).id();
        let peer2 = Peer(CompressedEdwardsY([2; 32])).id();
        let peer3 = Peer(CompressedEdwardsY([3; 32])).id();

        // none of the peers should be in the set
        assert!(!bloom.test(&peer1.0));
        assert!(!bloom.test(&peer2.0));
        assert!(!bloom.test(&peer3.0));

        // only peer1 should be in the set
        bloom.insert(&peer1.0);
        assert!(bloom.test(&peer1.0));
        assert!(!bloom.test(&peer2.0));
        assert!(!bloom.test(&peer3.0));

        // peer1 and peer2 should be in the set
        bloom.insert(&peer2.0);
        assert!(bloom.test(&peer1.0));
        assert!(bloom.test(&peer2.0));
        assert!(!bloom.test(&peer3.0));

        // all should be in the set
        bloom.insert(&peer3.0);
        assert!(bloom.test(&peer1.0));
        assert!(bloom.test(&peer2.0));
        assert!(bloom.test(&peer3.0));
    }

    #[test]
    fn vec() {
        let mut bloom = BloomFilter::new(128).unwrap();

        let peer1 = Peer(CompressedEdwardsY([1; 32])).id();
        let peer2 = Peer(CompressedEdwardsY([2; 32])).id();
        let peer3 = Peer(CompressedEdwardsY([3; 32])).id();

        // none of the peers should be in the set
        assert!(!bloom.test(&peer1.0));
        assert!(!bloom.test(&peer2.0));
        assert!(!bloom.test(&peer3.0));

        // only peer1 should be in the set
        bloom.insert(&peer1.0);
        assert!(bloom.test(&peer1.0));
        assert!(!bloom.test(&peer2.0));
        assert!(!bloom.test(&peer3.0));

        // peer1 and peer2 should be in the set
        bloom.insert(&peer2.0);
        assert!(bloom.test(&peer1.0));
        assert!(bloom.test(&peer2.0));
        assert!(!bloom.test(&peer3.0));

        // all should be in the set
        bloom.insert(&peer3.0);
        assert!(bloom.test(&peer1.0));
        assert!(bloom.test(&peer2.0));
        assert!(bloom.test(&peer3.0));
    }
}
