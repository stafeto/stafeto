# smoltcp 0.14.0, patched

This is smoltcp 0.14.0 from crates.io (licence: 0BSD, see LICENSE-0BSD.txt) with one change, in
`src/iface/interface/mod.rs`, `InterfaceInner::lookup_hardware_addr`: a destination that is an
address of the interface itself resolves to the interface's own hardware address, with no
neighbour cache lookup and no ARP request. The loopback of netd (127.0.0.1 is the second address of
the Ethernet interface) used to depend on seeded ARP entries, and a destination with no entry took
the interface-wide ARP slot (one request a second) and stalled it.

The manifest leaves out the examples, tests, benches and dev-dependencies; `src/`, `build.rs` and the
licence are unchanged otherwise. Remove this directory and the `[patch.crates-io]` entry of the
workspace manifest when smoltcp has the change.
