'use strict';

const sniff = require('./index.js');

sniff('192.168.0.3', (packet) => console.log(packet));