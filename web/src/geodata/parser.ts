// Pure-browser Protobuf reader for V2Ray/Xray geoip.dat & geosite.dat

export interface GeoCategorySummary {
  code: string;
  count: number;
}

class ProtoReader {
  private pos = 0;
  constructor(private readonly buf: Uint8Array) {}

  get eof(): boolean {
    return this.pos >= this.buf.length;
  }

  readVarint(): number {
    let result = 0;
    let shift = 0;
    let bytesRead = 0;
    while (this.pos < this.buf.length) {
      const b = this.buf[this.pos++];
      bytesRead++;
      if (bytesRead > 10 || shift >= 64) {
        throw new Error(`Malformed protobuf varint (>10 bytes) at offset ${this.pos}`);
      }
      if (shift < 32) {
        result |= (b & 0x7f) << shift;
      }
      if ((b & 0x80) === 0) return result >>> 0;
      shift += 7;
    }
    throw new Error(`Unexpected EOF while reading protobuf varint at offset ${this.pos}`);
  }

  readVarint32(): number {
    let result = 0;
    let shift = 0;
    let bytesRead = 0;
    while (this.pos < this.buf.length) {
      const b = this.buf[this.pos++];
      bytesRead++;
      if (bytesRead > 5 || (bytesRead === 5 && (b & 0xf0) !== 0)) {
        throw new Error(`Protobuf varint32 overflow at offset ${this.pos}`);
      }
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) return result >>> 0;
      shift += 7;
    }
    throw new Error(`Unexpected EOF while reading protobuf varint32 at offset ${this.pos}`);
  }

  readBytes(): Uint8Array {
    const len = this.readVarint32();
    if (len < 0 || this.pos + len > this.buf.length) {
      throw new Error(`Invalid protobuf length ${len} at offset ${this.pos}`);
    }
    const slice = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return slice;
  }

  skip(wireType: number): void {
    if (wireType === 0) this.readVarint();
    else if (wireType === 1) {
      if (this.pos + 8 > this.buf.length) throw new Error('Unexpected EOF skipping 64-bit field');
      this.pos += 8;
    } else if (wireType === 2) {
      this.readBytes();
    } else if (wireType === 5) {
      if (this.pos + 4 > this.buf.length) throw new Error('Unexpected EOF skipping 32-bit field');
      this.pos += 4;
    } else {
      throw new Error(`Unsupported protobuf wireType: ${wireType}`);
    }
  }
}

export function parseGeoDatIndex(buffer: ArrayBuffer): GeoCategorySummary[] {
  const root = new ProtoReader(new Uint8Array(buffer));
  const decoder = new TextDecoder();
  const categories: GeoCategorySummary[] = [];

  while (!root.eof) {
    const tag = root.readVarint();
    const field = tag >>> 3;
    const wire = tag & 7;
    if (field === 0) {
      throw new Error('Invalid protobuf field number 0');
    }
    if (field === 1 && wire === 2) {
      const entryReader = new ProtoReader(root.readBytes());
      let code = '';
      let count = 0;
      while (!entryReader.eof) {
        const etag = entryReader.readVarint();
        const efield = etag >>> 3;
        const ewire = etag & 7;
        if (efield === 0) {
          throw new Error('Invalid protobuf field number 0');
        }
        if (efield === 1 && ewire === 2) {
          code = decoder.decode(entryReader.readBytes()).toLowerCase();
        } else if (efield === 2 && ewire === 2) {
          entryReader.readBytes();
          count++;
        } else {
          entryReader.skip(ewire);
        }
      }
      if (code) categories.push({ code, count });
    } else {
      root.skip(wire);
    }
  }

  return categories.sort((a, b) => a.code.localeCompare(b.code));
}
