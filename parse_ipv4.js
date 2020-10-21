'use strict';

module.exports = function parse_ipv4_packet(buffer) {
  let offset = 0;
  const { sf_pkthdr, offset: offset_b } = read_sf_pkthdr(buffer, offset);
  offset = offset_b;
  const { packet, offset: offset_c } = read_packet(buffer, offset, sf_pkthdr);
  offset = offset_c;
  return packet;
}

function read_timeval(buffer, offset) {
  const tv_sec = buffer.readInt32LE(offset);
  offset += 32 / 8;
  const tv_usec = buffer.readInt32LE(offset);
  offset += 32 / 8;
  const timeval = { tv_sec, tv_usec };
  return { timeval, offset };
}

function read_ethernet_header(buffer, offset) {
  const mac_addr_dst = buffer.slice(offset, offset + 6).toString('hex').match(/../g).join(':');
  offset += 6;
  const mac_addr_src = buffer.slice(offset, offset + 6).toString('hex').match(/../g).join(':');
  offset += 6;
  const eth_type = buffer.readUInt16LE(offset);
  offset += 2;
  const ethernet_header = { mac_addr_dst, mac_addr_src, eth_type };
  return { ethernet_header, offset };
}

function read_sf_pkthdr(buffer, offset) {
  const { timeval: ts, offset: new_offset } = read_timeval(buffer, offset);
  offset = new_offset;
  const caplen = buffer.readUInt32LE(offset);
  offset += 32 / 8;
  const len = buffer.readUInt32LE(offset);
  offset += 32 / 8;
  const sf_pkthdr = { ts, caplen, len };
  return { sf_pkthdr, offset };
}

function read_ipv4_header(buffer, offset) {
  const ip_version_number = parseInt(buffer[offset].toString(16)[0], 16);
  offset += 0; // not a typo
  const ihl = parseInt(buffer[offset].toString(16)[1], 16);
  offset += 1;
  const service_type = buffer[offset];
  offset += 1;
  const total_length = buffer.readUInt16LE(offset);
  offset += 16 / 8;
  const id = buffer.readUInt16LE(offset);
  offset += 16 / 8;
  const flags = parseInt(buffer[offset].toString(16)[0], 16).toString(2).padStart(4, '0');
  offset += 0; // not a typo
  const fragment_offset = ((buffer[offset] & 0x0F) << 8) | (buffer[offset + 1] & 0xff); // needs to be fixed
  offset += 2;
  const time_to_live = buffer[offset];
  offset += 1;
  const protocol = buffer[offset];
  offset += 1;
  const header_checksum = buffer.readUInt16LE(offset);
  offset += 16 / 8;
  const src_addr = buffer.slice(offset, offset + (32 / 8)).toString('hex').match(/../g).map((byte) => parseInt(byte, 16)).join('.');
  offset += 32 / 8;
  const dst_addr = buffer.slice(offset, offset + (32 / 8)).toString('hex').match(/../g).map((byte) => parseInt(byte, 16)).join('.');
  offset += 32 / 8;

  const bytes_length = ihl * (32 / 8);
  if (bytes_length > 20) {
    offset += ((ihl - 5) * (32 / 8));
  }

  const ipv4_header = {
    ip_version_number,
    ihl,
    bytes_length,
    service_type,
    total_length,
    id,
    flags,
    fragment_offset,
    time_to_live,
    protocol: protocol == 17 ? 'UDP' : protocol,
    header_checksum,
    src_addr,
    dst_addr
  };
  return { ipv4_header, offset };
}

function read_packet_header(buffer, offset, protocol_number) {
  if (protocol_number == 'UDP') {
    return read_udp_header(buffer, offset);
  } else {
    return { packet_header: 'Non-UDP Packet Header', offset };
  }
}

function read_udp_header(buffer, offset) {
  const port_src = buffer.readUInt16BE(offset);
  offset += 16 / 8;
  const port_dst = buffer.readUInt16BE(offset);
  offset += 16 / 8;
  const length = buffer.readUInt16BE(offset);
  offset += 16 / 8;
  const checksum = buffer.readUInt16BE(offset);
  offset += 16 / 8;
  const udp_header = {
    port_src,
    port_dst,
    length,
    checksum
  };
  return { packet_header: udp_header, offset };
}

function read_packet(buffer, offset, { caplen: len }) {
  const original_offset = offset;
  const { ethernet_header, offset: new_offset_a } = read_ethernet_header(buffer, offset);
  if (ethernet_header.eth_type != 8) {
    const packet = 'Not IPv4';
    return { packet, offset };
  }
  offset = new_offset_a;
  const { ipv4_header, offset: new_offset_b } = read_ipv4_header(buffer, offset);
  offset = new_offset_b;
  if (ipv4_header.ip_version_number != 4) {
    const packet = 'Not IPv4';
    return { packet, offset };
  }
  const { packet_header, offset: new_offset_c } = read_packet_header(buffer, offset, ipv4_header.protocol);
  offset = new_offset_c;
  const payload = buffer.slice(new_offset_c, original_offset + len);
  offset = original_offset + len;
  const packet = { ethernet_header, ipv4_header, packet_header, payload };
  return { packet, offset };
}
