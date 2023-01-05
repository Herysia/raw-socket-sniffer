"use strict";
const { RawSocket } = require("./index.js");
const rs = new RawSocket("192.168.0.51", 443);
rs.on("data", (data) => {
  //We would like to have both directions here (working in Node 16), not working with electron (tested with v22 & v18)
  //Currently there is a std::cout which logs in/out ports which highlight the problem,
  //as you can see in the following video (Left=Electron v22.0.0, right=Node v16.15.1)
  //https://dl.dropboxusercontent.com/s/2m99yopiserbpcy/Code_2023-01-05_22-05-35.mp4
});
rs.listen();
