# raw-socket-sniffer

This branch is used as a bug repro for Electron.

# Usage:

## Setup

- Change the ip to your local interface IP you want to capture
- Change the port you want to filter (443 can easily have TCP traffic), or 0 for any (log may be flooded by UDP)
- Need to be run as Administrator for Raw sockets

### For Node test

- Build with `npm run rebuild`
- Run with `npm run start`

### For Electron test

- Build with `npm run rebuild:electron`
- Run with `npm run start:electron`

# Bug

We expect TCP packets to be captured on both sides, as it already the case for Node,
but when building and running with Electron, **only inbound TCP packets are captured** with `recv()`,
while both **inbound & outbound are captured for UDP** (on both Node & Electron)

See the following video of traffic captured with
Left: Electron v22.0.0
Right: Node v16.15.1

https://dl.dropboxusercontent.com/s/2m99yopiserbpcy/Code_2023-01-05_22-05-35.mp4
