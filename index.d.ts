import { EventEmitter } from "events";

export declare interface RawSocket {
  on(event: "data", listener: (data: Buffer) => void): this;
}

export class RawSocket extends EventEmitter {
  constructor(ip: string, port: number);
  listen(): void;
}
