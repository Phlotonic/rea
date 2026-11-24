import { createGunzip } from "node:zlib";
import { Readable } from "node:stream";
import { decodeLimit, malformedInput } from "../../domain/parseFailure.js";
import { NPM_PACKAGE_FORMAT } from "../../domain/javascript/npmPackage.js";

const TAR_BLOCK_SIZE = 512;

export type TarTypeFlag =
  | "file"
  | "directory"
  | "symlink"
  | "hardlink"
  | "other";

export interface TarEntryRecord {
  readonly path: string;
  readonly size: number;
  readonly typeFlag: TarTypeFlag;
  readonly linkTarget: string | null;
}

export interface ReadTarGzOptions {
  readonly maxEntries: number;
  readonly maxUncompressedBytes: number;
  readonly maxManifestBytes: number;
}

export interface ReadTarGzResult {
  readonly entries: readonly TarEntryRecord[];
  readonly uncompressedBytes: number;
  readonly manifestPath: string | null;
  readonly manifestBytes: Buffer | null;
  readonly manifestOversizeBytes: number | null;
}

const isZeroBlock = (buf: Buffer, offset: number): boolean => {
  const end = offset + TAR_BLOCK_SIZE;
  for (let i = offset; i < end; i += 1) {
    if (buf[i] !== 0) return false;
  }
  return true;
};

const readCString = (buf: Buffer, offset: number, length: number): string => {
  let end = offset;
  const max = offset + length;
  while (end < max && buf[end] !== 0) end += 1;
  return buf.subarray(offset, end).toString("utf8");
};

const parseTarOctal = (buf: Buffer, offset: number, length: number): number => {
  const first = buf[offset];
  if (first !== undefined && (first & 0x80) !== 0) {
    // GNU base-256 big-endian integer encoding.
    let value = 0;
    for (let i = 1; i < length; i += 1) {
      value = value * 256 + (buf[offset + i] ?? 0);
    }
    return Number.isSafeInteger(value) ? value : 0;
  }
  const raw = readCString(buf, offset, length).trim();
  if (raw === "") return 0;
  const parsed = Number.parseInt(raw, 8);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
};

const parsePaxRecords = (payload: Buffer): Map<string, string> => {
  const records = new Map<string, string>();
  const text = payload.toString("utf8");
  let pos = 0;
  while (pos < text.length) {
    const space = text.indexOf(" ", pos);
    if (space < 0) break;
    const len = Number.parseInt(text.slice(pos, space), 10);
    if (!Number.isFinite(len) || len <= 0) break;
    const record = text.slice(space + 1, pos + len);
    const eq = record.indexOf("=");
    if (eq > 0) {
      const key = record.slice(0, eq);
      const val = record.endsWith("\n")
        ? record.slice(eq + 1, -1)
        : record.slice(eq + 1);
      records.set(key, val);
    }
    pos += len;
  }
  return records;
};

const classifyTypeFlag = (flagByte: number): TarTypeFlag => {
  const ch = flagByte === 0 ? "0" : String.fromCharCode(flagByte);
  if (ch === "0" || ch === "\0") return "file";
  if (ch === "5") return "directory";
  if (ch === "2") return "symlink";
  if (ch === "1") return "hardlink";
  return "other";
};

const isPrimaryPackageManifest = (entryPath: string): boolean => {
  const cleaned = entryPath.replace(/^\.\//, "");
  if (cleaned === "package.json") return true;
  const parts = cleaned.split("/");
  return parts.length === 2 && parts[1] === "package.json";
};

const gunzipBounded = async (
  compressed: Buffer,
  maxUncompressedBytes: number,
): Promise<Buffer> => {
  if (compressed.length < 2 || compressed[0] !== 0x1f || compressed[1] !== 0x8b) {
    throw malformedInput(
      NPM_PACKAGE_FORMAT,
      "Input is not a valid gzip-compressed npm package tarball (.tgz).",
    );
  }
  const chunks: Buffer[] = [];
  let total = 0;
  const gunzip = createGunzip();
  const source = Readable.from(compressed);
  source.pipe(gunzip);
  try {
    for await (const chunk of gunzip) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > maxUncompressedBytes) {
        source.destroy();
        gunzip.destroy();
        throw decodeLimit(
          NPM_PACKAGE_FORMAT,
          `Decompressed tarball exceeds max_uncompressed_bytes (${String(maxUncompressedBytes)}).`,
          { name: "max_uncompressed_bytes", maximum: maxUncompressedBytes },
        );
      }
      chunks.push(buf);
    }
  } catch (error) {
    if (error instanceof Error && error.name === "ParseFailureError") {
      throw error;
    }
    throw malformedInput(
      NPM_PACKAGE_FORMAT,
      `Failed to gunzip npm package tarball: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
  return Buffer.concat(chunks, total);
};

interface TarOverrides {
  paxPath: string | null;
  paxLink: string | null;
  paxSize: number | null;
  gnuPath: string | null;
  gnuLink: string | null;
}

const clearOverrides = (): TarOverrides => ({
  paxPath: null,
  paxLink: null,
  paxSize: null,
  gnuPath: null,
  gnuLink: null,
});

/** Stream-decompress and parse a POSIX/USTAR/PAX/GNU npm `.tgz` tarball under strict ceilings. */
export const readNpmTarGz = async (
  compressed: Buffer,
  options: ReadTarGzOptions,
): Promise<ReadTarGzResult> => {
  const tar = await gunzipBounded(compressed, options.maxUncompressedBytes);
  const entries: TarEntryRecord[] = [];
  let offset = 0;
  let zeroBlocks = 0;
  let overrides = clearOverrides();
  let manifestPath: string | null = null;
  let manifestBytes: Buffer | null = null;
  let manifestOversizeBytes: number | null = null;

  while (offset + TAR_BLOCK_SIZE <= tar.length) {
    if (isZeroBlock(tar, offset)) {
      zeroBlocks += 1;
      offset += TAR_BLOCK_SIZE;
      if (zeroBlocks >= 2) break;
      continue;
    }
    zeroBlocks = 0;

    const flagByte = tar[offset + 156] ?? 0;
    const rawFlag = flagByte === 0 ? "0" : String.fromCharCode(flagByte);
    const headerSize = parseTarOctal(tar, offset + 124, 12);
    const size = overrides.paxSize ?? headerSize;
    const dataStart = offset + TAR_BLOCK_SIZE;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.length) {
      throw malformedInput(
        NPM_PACKAGE_FORMAT,
        "Truncated tar entry payload in npm package tarball.",
      );
    }
    const nextOffset =
      dataStart + Math.ceil(size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;

    if (rawFlag === "x" || rawFlag === "g") {
      const pax = parsePaxRecords(tar.subarray(dataStart, dataEnd));
      if (rawFlag === "x") {
        overrides.paxPath = pax.get("path") ?? overrides.paxPath;
        overrides.paxLink = pax.get("linkpath") ?? overrides.paxLink;
        const rawPaxSize = pax.get("size");
        if (rawPaxSize !== undefined) {
          const parsedSize = Number.parseInt(rawPaxSize, 10);
          if (Number.isSafeInteger(parsedSize) && parsedSize >= 0) {
            overrides.paxSize = parsedSize;
          }
        }
      }
      offset = nextOffset;
      continue;
    }
    if (rawFlag === "L") {
      overrides.gnuPath = readCString(tar, dataStart, size);
      offset = nextOffset;
      continue;
    }
    if (rawFlag === "K") {
      overrides.gnuLink = readCString(tar, dataStart, size);
      offset = nextOffset;
      continue;
    }

    const baseName = readCString(tar, offset, 100);
    const prefix = readCString(tar, offset + 345, 155);
    const ustarName = prefix !== "" ? `${prefix}/${baseName}` : baseName;
    const entryPath = overrides.paxPath ?? overrides.gnuPath ?? ustarName;
    const headerLink = readCString(tar, offset + 157, 100);
    const rawLink = overrides.paxLink ?? overrides.gnuLink ?? headerLink;
    const typeFlag = classifyTypeFlag(flagByte);
    const linkTarget =
      typeFlag === "symlink" || typeFlag === "hardlink"
        ? rawLink || null
        : null;

    overrides = clearOverrides();

    if (entries.length >= options.maxEntries) {
      throw decodeLimit(
        NPM_PACKAGE_FORMAT,
        `Tarball member count exceeds max_entries (${String(options.maxEntries)}).`,
        { name: "max_entries", maximum: options.maxEntries },
      );
    }

    entries.push({ path: entryPath, size, typeFlag, linkTarget });

    if (
      typeFlag === "file" &&
      manifestPath === null &&
      isPrimaryPackageManifest(entryPath)
    ) {
      manifestPath = entryPath;
      if (size <= options.maxManifestBytes) {
        manifestBytes = Buffer.from(tar.subarray(dataStart, dataEnd));
      } else {
        manifestOversizeBytes = size;
      }
    }

    offset = nextOffset;
  }

  return {
    entries,
    uncompressedBytes: tar.length,
    manifestPath,
    manifestBytes,
    manifestOversizeBytes,
  };
};
