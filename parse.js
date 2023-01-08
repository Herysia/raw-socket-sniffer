const fs = require("fs");

const data = fs.readFileSync("log2.txt", "utf-8");
fs.writeFileSync("out.txt", "");
let cp = [];
let rs = [];
const split = data.split(/\r?\n/);
split.forEach((line) => {
  if (line.startsWith("cp")) {
    cp.push(line.split(" ")[1]);
  } else if (line.startsWith("rs")) {
    rs.push(line.split(" ")[1]);
  }
});
split.forEach((line) => {
  if (line.startsWith("cp") || line.startsWith("rs")) {
    fs.appendFileSync("out.txt", line.replace(" ", ` - ${cp.indexOf(line.split(" ")[1])} - `) + "\n");
  }
});
console.log(cp.length, rs.length);
for (let i = 0; i < cp.length; i++) {
  if (!cp.includes(rs[i])) {
    console.log("Diff found, cp:" + i);
  }
  if (!rs.includes(cp[i])) {
    console.log("Diff found, rs:" + i);
  }
  if (rs[i] != cp[i]) console.log(i);
  if (i == cp.length - 1) {
    console.log("no diff");
    break;
  }
}
