
# raw-socket-sniffer

This repository is a fork of [nospaceships/raw-socket-sniffer](https://github.com/nospaceships/raw-socket-sniffer) rewritten as an NPM package.

The programs require no additional software, such as WinPCAP or npcap, and will
simply use existing operating system functionality.

## Example Usage
```javascript
'use strict';
const sniff = require('raw-socket-sniffer');
sniff('192.168.0.3', (packet) => console.log(packet));
```

## Example Output
```javascript
{
  ethernet_header: {
    mac_addr_dst: '00:00:00:00:00:00', // fake, always zeros
    mac_addr_src: '00:00:00:00:00:00', // fake, always zeros
    eth_type: 8 // always 8
  },
  ipv4_header: {
    ip_version_number: 4, // always 4
    ihl: 5,
    bytes_length: 20,
    service_type: 0,
    total_length: 22784,
    id: 40055,
    flags: '0000',
    fragment_offset: 0, // incorrect due to unfixed bug in parse_ipv4.js
    time_to_live: 255,
    protocol: 'UDP',
    header_checksum: 16034,
    src_addr: 'xxx.xxx.xxx.xxx',
    dst_addr: 'xxx.xxx.xxx.xxx'
  },
  packet_header: { port_src: 5353, port_dst: 5353, length: 69, checksum: 11246 }, // only UDP packets are parsed
  payload: <Buffer 00 00 00 00 00 01 33 70 00 00 00 00 08 1f 61 69>
}
```

## Ethernet Headers

The programs in this repository use raw sockets to capture IP packets.  A side
effect of this is that no ethernet header is included in the data received.  If
it is required to capture ethernet header data then another tool should be used.

Since the original program produces PCAP files, and PCAP files include fully formed
packets, a fake ethernet header is synthesized for each packet using the all
zeros source and destination ethernet addresses.

This does not affect other protocol layers, and, for example, TCP streams
can still be reassembled, and IP layer source and destination addresses are
all still valid.
