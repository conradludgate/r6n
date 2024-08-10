use crate::{Message, Peer};

/// R5N does not specify an underlay network. This is the application's
/// responsibility to provide.
pub trait Underlay {
    type Address;
    type NetworkSizeEstimate;

    /// This call allows the DHT implementation to signal to the underlay that
    /// the DHT wants to establish a connection to the target peer using the
    /// given address. If the connection attempt is successful, information
    /// on the new peer connection will be offered through the `peer_connected`
    /// signal.
    fn try_connect(peer: Peer, addr: Self::Address);

    /// This call tells the underlay to hold on to a connection to a peer.
    /// Underlays are usually limited in the number of active connections.
    /// With this function the DHT can indicate to the underlay which
    /// connections should preferably be preserved.
    fn hold(peer: Peer);

    /// This call tells the underlay to drop the connection to a peer. This
    /// call is only there for symmetry and used during the peer's shutdown to
    /// release all of the remaining [`hold`](Underlay::hold)s. As R5N always
    /// prefers the longest-lived connections, it would never drop an active
    /// connection that it has called [`hold`](Underlay::hold) on before.
    /// Nevertheless, underlay implementations should not rely on this always
    /// being true. A call to [`drop`] also does not imply that the underlay
    /// must close the connection: it merely removes the preference to preserve
    /// the connection that was established by [`hold`](Underlay::hold).
    fn drop(peer: Peer);

    /// This call allows the local peer to send a protocol message to a peer.
    /// Sending messages is expected to be done on a best-effort basis, thus
    /// the underlay does not have to guarantee delivery or message ordering.
    /// If the underlay implements flow- or congestion-control, it may discard
    /// messages to limit its queue size.
    fn send(peer: Peer, message: Message);

    /// This call must return an estimate of the network size. The resulting
    /// [`NetworkSizeEstimate`](Underlay::NetworkSizeEstimate) value must be
    /// the estimated number of peers in the network. This estimate is used by
    /// the routing algorithm. If the underlay does not support a protocol for
    /// network size estimation the value is assumed to be provided as a
    /// configuration parameter to the underlay implementation.
    fn estimate_network_size(&self) -> Self::NetworkSizeEstimate;
}

pub enum UnderlaySignal<U: Underlay> {
    /// This signal allows the DHT to react to a newly connected peer. Such an
    /// event triggers, for example, updates in the routing table and gossiping
    /// of `HELLO`s to that peer. Underlays may include meta-data about the
    /// connection, for example to indicate that the connection is from a
    /// resource-constrained host that does not intend to function as a full
    /// peer and thus should not be considered for routing.
    PeerConnected(Peer),
    /// This signal allows the DHT to react to a recently disconnected peer.
    /// Such an event primarily triggers updates in the routing table.
    PeerDisconnected(Peer),
    /// The underlay signals indicates that an address A was added for our
    /// local peer and that henceforth the peer may be reachable under this
    /// address. This information is used to advertise connectivity information
    /// about the local peer to other peers. A is an address suitable for
    /// inclusion in a HELLO payload Section 8.2.
    AddressAdded(U::Address),
    /// This underlay signal indicates that an address A was removed from the
    /// set of addresses the local peer is possibly reachable under. The signal
    /// is used to stop advertising this address to other peers.
    AddressDeleted(U::Address),
    /// This signal informs the local peer that a protocol message was received
    /// from a peer.
    Receive(Peer, Message),
}
