use zerocopy::{big_endian, FromBytes, FromZeroes};

use crate::PeerId;

pub struct BloomFilter {
    bits: [u8; 128],
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self { bits: [0u8; 128] }
    }
}

impl BloomFilter {
    /// return true if id is in the filter
    pub fn test(&self, id: &PeerId) -> bool {
        let keys = Keys::ref_from(&id.0).unwrap();

        for k in keys.0 {
            let bit = k.get() % 1024;
            let byte = bit / 8;
            let bit = bit % 8;
            if self.bits[byte as usize] >> bit & 1 == 0 {
                return false;
            }
        }

        true
    }

    pub fn insert(&mut self, id: &PeerId) {
        let keys = Keys::ref_from(&id.0).unwrap();

        for k in keys.0 {
            let bit = k.get() % 1024;
            let byte = bit / 8;
            let bit = bit % 8;
            self.bits[byte as usize] |= 1 << bit;
        }
    }
}

#[derive(FromBytes, FromZeroes)]
struct Keys([big_endian::U32; 16]);

#[cfg(test)]
mod tests {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    use crate::Peer;

    use super::BloomFilter;

    #[test]
    fn happy() {
        let mut bloom = BloomFilter::default();

        let peer1 = Peer(CompressedEdwardsY([1; 32])).id();
        let peer2 = Peer(CompressedEdwardsY([2; 32])).id();
        let peer3 = Peer(CompressedEdwardsY([3; 32])).id();

        // none of the peers should be in the set
        assert!(!bloom.test(&peer1));
        assert!(!bloom.test(&peer2));
        assert!(!bloom.test(&peer3));

        // only peer1 should be in the set
        bloom.insert(&peer1);
        assert!(bloom.test(&peer1));
        assert!(!bloom.test(&peer2));
        assert!(!bloom.test(&peer3));

        // peer1 and peer2 should be in the set
        bloom.insert(&peer2);
        assert!(bloom.test(&peer1));
        assert!(bloom.test(&peer2));
        assert!(!bloom.test(&peer3));

        // all should be in the set
        bloom.insert(&peer3);
        assert!(bloom.test(&peer1));
        assert!(bloom.test(&peer2));
        assert!(bloom.test(&peer3));
    }
}
