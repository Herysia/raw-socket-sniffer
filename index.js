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

module.exports = { RawSocket };
