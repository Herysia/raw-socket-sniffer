'use strict';

const { sniff } = require('bindings')('/release/addon');
const parse = require('./parse_ipv4.js');

module.exports = function (destination_ip_address, callback) {
  const _END_OF_PACKET_ = '_END_OF_PACKET_';
  const bytes = [];
  const chars = [];
  sniff(destination_ip_address, (byte) => {
    const char = String.fromCharCode(parseInt(byte.toString(16), 16));
    const hex = byte.toString(16).padStart(2, '0');
    const dec = parseInt(byte.toString(16), 16);
    bytes.push(byte);
    chars.push(char);
    if (chars.length >= _END_OF_PACKET_.length && chars.join('').endsWith(_END_OF_PACKET_)) {
      const packet = parse(Buffer.from(bytes.slice(0, -_END_OF_PACKET_.length)));
      callback(packet);
      bytes.length = 0;
      chars.length = 0;
    }
  });
}

