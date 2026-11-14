# smoltcp 0.14.0, patched

This is smoltcp 0.14.0 from crates.io (licence: 0BSD, see LICENSE-0BSD.txt) with two changes.

1. In
`src/iface/interface/mod.rs`, `InterfaceInner::lookup_hardware_addr`: a destination that is an
address of the interface itself resolves to the interface's own hardware address, with no
neighbour cache lookup and no ARP request. The loopback of netd (127.0.0.1 is the second address of
the Ethernet interface) used to depend on seeded ARP entries, and a destination with no entry took
the interface-wide ARP slot (one request a second) and stalled it.

2. In `src/iface/interface/ipv4.rs`, `InterfaceInner::process_ipv4`: a unicast IPv4 packet whose
   source is on the link of the interface (not one of its own addresses, not loopback) fills the
   neighbour cache with the source's hardware address before the packet is processed. Upstream only
   renews an entry that exists. The reset to a SYN for a port with no listener is sent once, and
   with no entry the stack dropped it (and sent an ARP request, one a second for the whole
   interface), so the peer saw the reset only after its own SYN retransmission a second later
   (stafeto-design#730). The test is `tests/neighbour-learn` (`cargo test -p neighbour-learn`).

The manifest leaves out the examples, tests, benches and dev-dependencies; `src/`, `build.rs` and the
licence are unchanged otherwise. Remove this directory and the `[patch.crates-io]` entry of the
workspace manifest when smoltcp has the change.
