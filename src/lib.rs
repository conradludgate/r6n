use std::{
    mem,
    time::{Duration, Instant},
};

use curve25519_dalek::edwards::CompressedEdwardsY;

pub mod block;
pub mod bloom;
pub mod message;
pub mod underlay;

// as far as I can tell, R5N requires EdDSA (Ed25519).
#[derive(PartialEq, Eq)]
pub struct Peer(curve25519_dalek::edwards::CompressedEdwardsY);

impl PartialOrd for Peer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Peer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Ord::cmp(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl Peer {
    fn id(&self) -> PeerId {
        use sha2::Digest;
        PeerId(sha2::Sha512::digest(self.0.as_bytes()).into())
    }
}

pub struct PeerId([u8; 64]);
pub struct Message;

pub struct RoutingTable {
    host: PeerId,
    epoch: Instant,
    neighbours: Vec<u8>,
    routes: Vec<Route>,
}

impl RoutingTable {
    fn insert(&mut self, peer: Peer) -> Result<(), Peer> {
        let id = peer.id();
        let dist = log2_xor_dist(&self.host, &id);
        self.neighbours[dist as usize] += 1;

        let created = Instant::now().duration_since(self.epoch);
        let new_route = Route {
            dist,
            created,
            peer,
        };

        match self.routes.binary_search(&new_route) {
            // peer already inserted? disconnect previous
            Ok(i) => Err(mem::replace(&mut self.routes[i], new_route).peer),
            Err(i) => {
                self.routes.insert(i, new_route);
                Ok(())
            }
        }
    }

    /// Find the last peer in this k-bucket. corresponds to the shortest lived connection.
    fn last_k(&self, dist: u16) -> Option<usize> {
        if self.neighbours[dist as usize] == 0 {
            return None;
        }

        let successor = Route {
            dist: dist + 1,
            created: Duration::ZERO,
            peer: Peer(CompressedEdwardsY([0; 32])),
        };

        let last = match self.routes.binary_search(&successor) {
            // this is the first of the next dist
            // subtract 1 to get the last of the prev dist
            Ok(i) => i.checked_sub(1)?,
            // this is where the first of the next dist should get inserted
            // which would be just after this dist.
            Err(i) => i.checked_sub(1)?,
        };

        if self.routes[last].dist != dist {
            return None;
        }

        Some(last)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Route {
    // log2 XOR distance from peer to host
    dist: u16,
    created: Duration,
    peer: Peer,
}

pub fn log2_xor_dist(peer1: &PeerId, peer2: &PeerId) -> u16 {
    let mut dist = 0;

    #[allow(clippy::needless_range_loop)]
    for i in 0..64 {
        let xor = peer1.0[i] ^ peer2.0[i];
        let clz = xor.leading_zeros() as u16;
        dist += clz;
        if clz < 8 {
            break;
        }
    }

    512 - dist
}

pub fn xor(x: &[u8; 64], y: &[u8; 64]) -> [u8; 64] {
    let mut out = [0; 64];

    #[allow(clippy::needless_range_loop)]
    for i in 0..64 {
        out[i] = x[i] ^ y[i];
    }

    out
}

#[cfg(test)]
mod tests {
    use crate::{log2_xor_dist, PeerId};

    #[test]
    fn xor_dist() {
        let peer1 = PeerId([0; 64]);
        let mut peer2 = PeerId([0; 64]);
        let mut peer3 = PeerId([0; 64]);

        peer2.0[5] ^= 1 << 4;
        peer3.0[13] ^= 1 << 2;

        assert_eq!((63 - 5) * 8 + (4 + 1), 469);
        assert_eq!(log2_xor_dist(&peer1, &peer2), 469);
        assert_eq!(log2_xor_dist(&peer2, &peer1), 469);

        assert_eq!((63 - 13) * 8 + (2 + 1), 403);
        assert_eq!(log2_xor_dist(&peer1, &peer3), 403);
        assert_eq!(log2_xor_dist(&peer3, &peer1), 403);

        assert_eq!(log2_xor_dist(&peer2, &peer3), 469);
        assert_eq!(log2_xor_dist(&peer3, &peer2), 469);
    }
}
