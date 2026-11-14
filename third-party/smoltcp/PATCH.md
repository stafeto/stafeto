# smoltcp 0.14.0, patched

This is smoltcp 0.14.0 from crates.io (licence: 0BSD, see LICENSE-0BSD.txt) with two changes.

1. In `src/iface/interface/mod.rs`, `InterfaceInner::lookup_hardware_addr`: a destination that is
   an address of the interface itself resolves to the interface's own hardware address, with no
   neighbour cache lookup and no ARP request. The loopback of netd (127.0.0.1 is the second address
   of the Ethernet interface) used to depend on seeded ARP entries, and a destination with no entry
   took the interface-wide ARP slot (one request a second) and stalled it.

2. In `src/iface/interface/ipv4.rs`, `InterfaceInner::process_ipv4`, with `fill_if_vacant` in
   `src/iface/neighbor.rs`: a unicast IPv4 packet whose source is on the link of the interface
   (other than its own addresses and loopback) teaches the neighbour cache the source's hardware
   address before the packet is processed, only when the cache has no live entry for that address
   and has a free slot. It never overwrites a live entry and never evicts one, so a spoofed packet
   cannot replace the gateway's entry and sources on the link cannot push it out of the cache.
   Upstream only renews an entry that exists. The reset to a SYN for a port with no listener is sent
   once, and with no entry the stack dropped it (and sent an ARP request, one a second for the
   whole interface), so the peer saw the reset only after its own SYN retransmission a second later
   (stafeto-design#730). The tests are in `tests/neighbour-learn` (`cargo test -p neighbour-learn`).

The manifest leaves out the examples, tests, benches and dev-dependencies; `src/`, `build.rs` and the
licence are unchanged otherwise. Remove this directory and the `[patch.crates-io]` entry of the
workspace manifest when smoltcp has both changes.
