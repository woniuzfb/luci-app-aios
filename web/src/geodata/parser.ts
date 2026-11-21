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
    while (this.pos < this.buf.length) {
      const b = this.buf[this.pos++];
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) return result >>> 0;
      shift += 7;
    }
    return result >>> 0;
  }

  readBytes(): Uint8Array {
    const len = this.readVarint();
    const slice = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return slice;
  }

  skip(wireType: number): void {
    if (wireType === 0) this.readVarint();
    else if (wireType === 1) this.pos += 8;
    else if (wireType === 2) this.readBytes();
    else if (wireType === 5) this.pos += 4;
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
    if (field === 1 && wire === 2) {
      const entryReader = new ProtoReader(root.readBytes());
      let code = '';
      let count = 0;
      while (!entryReader.eof) {
        const etag = entryReader.readVarint();
        const efield = etag >>> 3;
        const ewire = etag & 7;
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
