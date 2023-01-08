const { RawSocket } = require("./index.js");
const Cap = require("cap").Cap;
var decoders = require("cap").decoders;
var PROTOCOL = decoders.PROTOCOL;

let rsCount = 0;
let rsLen = 0;
const port = 443;
const rs2 = new RawSocket("192.168.206.1", port);
rs2.listen();
const rs = new RawSocket("192.168.0.51", port);
rs.on("data", (data) => {
  const eth = decoders.Ethernet(data);
  if (eth.info.type === PROTOCOL.ETHERNET.IPV4) {
    const ip = decoders.IPV4(data, eth.offset);
    if (ip.info.protocol === PROTOCOL.IP.TCP) {
      rsLen += ip.info.totallen;
      rsCount++;
      const tcp = decoders.TCP(data, ip.offset);
      const dataLength = ip.info.totallen - 14;
      if (dataLength > 0) console.log("rs", data.subarray(14, 14 + dataLength).toString("hex"));
      if (ip.info.totallen + 14 != data.length) process.exit();
    }
  }
});
const c = new Cap();
const device = Cap.findDevice("192.168.0.51");
const filter = `(tcp or udp) and (dst port ${port} or src port ${port})`;
const bufSize = 10 * 1024 * 1024;
const buffer = Buffer.alloc(65535);
const capData = { c, buffer, device, len: 0, count: 0 };

const linkType = c.open(device, filter, bufSize, buffer);

c.setMinBytes && c.setMinBytes(0);

rs.listen();
c.on("packet", function (nbytes, trunc) {
  if (linkType === "ETHERNET") {
    const eth = decoders.Ethernet(buffer);

    if (eth.info.type === PROTOCOL.ETHERNET.IPV4) {
      const ip = decoders.IPV4(buffer, eth.offset);
      if (ip.info.protocol === PROTOCOL.IP.TCP) {
        capData.len += ip.info.totallen;
        capData.count++;
        const tcp = decoders.TCP(buffer, ip.offset);
        const dataLength = ip.info.totallen - 14;
        if (dataLength > 0) console.log("cp", buffer.subarray(14, 14 + dataLength).toString("hex"));
      }
      //console.log(`Cap: ${ip.info.totallen} - ${capData.len}(${capData.count})`);
    }
  }
});
setInterval(() => {
  console.log(`cap/socket : ${capData.len}(${capData.count})/${rsLen}(${rsCount})`);
}, 1000);
