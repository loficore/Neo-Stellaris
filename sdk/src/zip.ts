// zip.ts — the smallest ZIP writer/reader that `neo pack` needs.
//
// Why not a dependency: the pack output is the author's shippable artifact, and
// a store-only ZIP is ~100 lines with no native module, no install script and a
// fully deterministic byte layout (fixed 1980-01-01 timestamp).  That makes the
// pack reproducible — two runs over the same inputs produce the same bytes —
// which a compressor with a wall-clock timestamp would not.
//
// The reader exists for `neo pack`'s own write-back verification and for the
// tests; it accepts stored entries and (defensively) deflated ones.

import { inflateRawSync } from "node:zlib";

export interface ZipEntry {
  /** Forward-slash relative path; directories are implicit. */
  name: string;
  data: Buffer;
}

export interface ZipEntryInfo {
  name: string;
  /** Uncompressed size in bytes. */
  size: number;
  crc: number;
  method: number;
  /** Offset of the local file header. */
  offset: number;
}

const LOCAL_SIG = 0x04034b50;
const CENTRAL_SIG = 0x02014b50;
const EOCD_SIG = 0x06054b50;
/** DOS date for 1980-01-01: ((year-1980) << 9) | (month << 5) | day. */
const DOS_DATE = 0x0021;
const DOS_TIME = 0x0000;
const UTF8_FLAG = 0x0800;
const STORE = 0;
const DEFLATE = 8;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function isAscii(name: string): boolean {
  return /^[\x20-\x7e]*$/.test(name);
}

function checkName(name: string): void {
  if (name.length === 0) throw new Error("zip: empty entry name");
  if (name.startsWith("/") || name.includes("\\")) {
    throw new Error(`zip: entry name must be a relative POSIX path: ${name}`);
  }
  if (name.split("/").includes("..")) {
    throw new Error(`zip: entry name escapes the root: ${name}`);
  }
}

/** Build a ZIP archive from `entries`, sorted by name. */
export function createZip(entries: readonly ZipEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const seen = new Set<string>();
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;

  for (const entry of sorted) {
    checkName(entry.name);
    if (seen.has(entry.name)) throw new Error(`zip: duplicate entry ${entry.name}`);
    seen.add(entry.name);

    const name = Buffer.from(entry.name, "utf8");
    const flags = isAscii(entry.name) ? 0 : UTF8_FLAG;
    const crc = crc32(entry.data);

    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(LOCAL_SIG, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(STORE, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(entry.data.length, 18);
    local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    name.copy(local, 30);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(CENTRAL_SIG, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(STORE, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(entry.data.length, 20);
    central.writeUInt32LE(entry.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30); // extra length
    central.writeUInt16LE(0, 32); // comment length
    central.writeUInt16LE(0, 34); // disk number
    central.writeUInt16LE(0, 36); // internal attributes
    central.writeUInt32LE(0, 38); // external attributes
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);

    locals.push(local, entry.data);
    centrals.push(central);
    offset += local.length + entry.data.length;
  }

  const centralDir = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(EOCD_SIG, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(centrals.length, 8);
  eocd.writeUInt16LE(centrals.length, 10);
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...locals, centralDir, eocd]);
}

/** List the entries of a ZIP archive, in central-directory order. */
export function listZip(archive: Buffer): ZipEntryInfo[] {
  let eocd = -1;
  for (let i = archive.length - 22; i >= 0; i--) {
    if (archive.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("zip: no end-of-central-directory record");

  const total = archive.readUInt16LE(eocd + 10);
  let cursor = archive.readUInt32LE(eocd + 16);
  const out: ZipEntryInfo[] = [];
  for (let i = 0; i < total; i++) {
    if (cursor + 46 > archive.length || archive.readUInt32LE(cursor) !== CENTRAL_SIG) {
      throw new Error("zip: corrupt central directory");
    }
    const method = archive.readUInt16LE(cursor + 10);
    const crc = archive.readUInt32LE(cursor + 16);
    const size = archive.readUInt32LE(cursor + 24);
    const nameLen = archive.readUInt16LE(cursor + 28);
    const extraLen = archive.readUInt16LE(cursor + 30);
    const commentLen = archive.readUInt16LE(cursor + 32);
    const offset = archive.readUInt32LE(cursor + 42);
    const name = archive.toString("utf8", cursor + 46, cursor + 46 + nameLen);
    out.push({ name, size, crc, method, offset });
    cursor += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

/** Read one entry's bytes by name. */
export function readZipEntry(archive: Buffer, name: string): Buffer {
  const info = listZip(archive).find((entry) => entry.name === name);
  if (!info) throw new Error(`zip: no entry ${name}`);
  if (archive.readUInt32LE(info.offset) !== LOCAL_SIG) {
    throw new Error(`zip: corrupt local header for ${name}`);
  }
  const nameLen = archive.readUInt16LE(info.offset + 26);
  const extraLen = archive.readUInt16LE(info.offset + 28);
  const start = info.offset + 30 + nameLen + extraLen;
  const raw = archive.subarray(start, start + archive.readUInt32LE(info.offset + 18));
  if (info.method === STORE) return Buffer.from(raw);
  if (info.method === DEFLATE) return inflateRawSync(raw);
  throw new Error(`zip: unsupported compression method ${info.method} for ${name}`);
}
