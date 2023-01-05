"use strict";
const { EventEmitter } = require("events");
const { inherits } = require("util");

const { RawSocketCapture } = require("bindings")("addon");

inherits(RawSocketCapture, EventEmitter);
class RawSocket extends EventEmitter {
  constructor(ip, port) {
    super();
    this.binding = new RawSocketCapture(ip, port);
    this.binding.on("data", (data) => {
      this.emit("data", data);
    });
  }
  listen() {
    this.binding.listen();
  }
}
const rsc = new RawSocket("192.168.0.51", 0);
rsc.on("data", (data) => {
  console.log(data.subarray(0, 14).toString("hex"));
});
rsc.listen();
/*
const rsc2 = new RawSocket("172.19.192.1", 0);
rsc2.on("data", (data) => {
  console.log(2, data.length);
});
rsc2.listen();
*/
