use std::time::Instant;

pub mod underlay;
pub mod bloom;

pub struct Peer;
pub struct PeerId([u8; 64]);
pub struct Message;

pub struct RoutingTable {
    host: PeerId,
    neighbours: Vec<u8>,
    routes: Vec<Route>,
}

impl RoutingTable {
    fn insert(&mut self, peer: Peer, id: &PeerId) {
        let dist = log2_xor_dist(&self.host, id);
        self.neighbours[dist as usize] += 1;

        let created = Instant::now();
        let index = self
            .routes
            .binary_search_by_key(&(dist, created), |route| (route.dist, route.created))
            .expect_err("duplicate peer should not exist");

        self.routes.insert(
            index,
            Route {
                dist,
                created,
                peer,
            },
        )
    }
}

struct Route {
    // log2 XOR distance from peer to host
    dist: u16,
    created: Instant,
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
