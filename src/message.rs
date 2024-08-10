use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::ed25519::SignatureBytes;
use zerocopy::{big_endian, AsBytes, FromBytes, FromZeroes};

use crate::Peer;

// https://datatracker.ietf.org/doc/html/draft-schanzen-r5n-05#section-7.2
pub struct HelloMessage {}

// https://datatracker.ietf.org/doc/html/draft-schanzen-r5n-05#section-7.3
pub struct PutMessage {}

// https://datatracker.ietf.org/doc/html/draft-schanzen-r5n-05#section-7.4
pub struct GetMessage {}

// https://datatracker.ietf.org/doc/html/draft-schanzen-r5n-05#section-7.4
pub struct ResultMessage {}
