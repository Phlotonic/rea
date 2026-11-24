import { createHash } from "node:crypto";
import {
  Reader,
  Uint8ArrayWriter,
  Writer,
  ZipReader,
  type Entry,
  type FileEntry,
} from "@zip.js/zip.js";

import { Budget } from "../domain/budget.js";
import type { PrefixedByteSource } from "../domain/byteSource.js";
import {
  decodeLimit,
  malformedInput,
  ParseFailureError,
  unsupportedInput,
} from "../domain/parseFailure.js";
import {
  PYTHON_WHEEL_FORMAT,
  pythonWheelEntryRole,
  pythonWheelLogicalPath,
  type InspectPythonWheelInput,
  type PythonWheel,
} from "../domain/python/pythonWheel.js";
import { redactRecordedTransportUrl } from "../domain/recordedTransportUrl.js";
import { accountZipMemberRegion } from "../domain/zip/zipMemberRegion.js";
import { hasZipSignature } from "../domain/zipPackageFormat.js";
import {
  ArtifactReaderFailure,
  assertArtifactReadActive,
  decodeZipEntryText,
  typedZipFailure,
  ZIP_READER_OPTIONS,
  zipEntryNameLimitations,
  zipEntryPath,
  zipListingCoverage,
} from "../resources/index.js";

/** Limitation wording owned by the parser; tests assert delivery through these. */
export const PYTHON_WHEEL_LIMITATIONS = {
  staticOnly:
    "This workflow reads the .whl ZIP and *.dist-info metadata without installing, importing, executing code, or accessing the network.",
  noSafetyProof:
    "Metadata declarations and RECORD hashes describe archive contents only; they do not prove runtime behavior, dependency resolution results, or package safety.",
  directoryMarkersOmitted:
    "Directory ZIP markers are omitted from contents; only file members are listed.",
  noDistInfo: "No *.dist-info directory was found at the archive root.",
  ambiguousDistInfo:
    "Multiple root *.dist-info directories are present; wheel metadata was not decoded.",
  recordSkipped:
    "RECORD integrity verification was skipped by caller selection (verify_record=false).",
} as const;

const BASE_LIMITATIONS = [
  PYTHON_WHEEL_LIMITATIONS.staticOnly,
  PYTHON_WHEEL_LIMITATIONS.noSafetyProof,
  PYTHON_WHEEL_LIMITATIONS.directoryMarkersOmitted,
] as const;

const SUPPORTED_RECORD_ALGORITHMS = new Set(["sha256", "sha384", "sha512"]);
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

const nonempty = (value: string | null | undefined): string | null => {
  if (value === null || value === undefined) return null;
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
};

const zipSize = (value: number | undefined): number | null =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : null;

const asFileEntry = (entry: Entry): entry is FileEntry =>
  !entry.directory && typeof entry.getData === "function";

const wrapZipFailure = (cause: unknown, compressionMethod?: number): never => {
  if (cause instanceof ParseFailureError) throw cause;
  const typed = typedZipFailure(cause, compressionMethod);
  if (typed instanceof ArtifactReaderFailure && typed.reason === "limit")
    throw typed;
  if (typed instanceof ArtifactReaderFailure && typed.reason === "unavailable")
    throw unsupportedInput(
      PYTHON_WHEEL_FORMAT,
      `Python wheel ZIP uses an unsupported layout: ${typed.message}`,
      { cause: typed },
    );
  if (typed instanceof ArtifactReaderFailure && typed.reason === "format")
    throw malformedInput(PYTHON_WHEEL_FORMAT, typed.message, { cause: typed });
  throw cause;
};

/** Refuse expansion past the metadata budget before buffering more output. */
class BoundedUint8ArrayWriter extends Uint8ArrayWriter {
  readonly #budget: Budget;

  constructor(
    maximum: number,
    private readonly exceeded: (required: number) => Error,
  ) {
    super();
    this.#budget = new Budget(maximum);
  }

  override async init(size?: number): Promise<void> {
    if (size !== undefined && size > this.#budget.maximum)
      throw this.exceeded(size);
    await super.init?.(size);
  }

  override async writeUint8Array(array: Uint8Array): Promise<void> {
    this.#budget.charge(array.length, () =>
      this.exceeded(this.#budget.used + array.length),
    );
    await super.writeUint8Array(array);
  }
}

class RecordVerifyBudgetError extends Error {
  constructor(readonly required: number) {
    super("RECORD verification byte budget exceeded");
    this.name = "RecordVerifyBudgetError";
  }
}

/** Stream-hash one member without buffering its full decompressed contents. */
class BoundedHashWriter extends Writer<{
  readonly digest: string;
  readonly bytes: number;
}> {
  readonly #hash: ReturnType<typeof createHash>;
  readonly #remainingBudget: number;
  #bytes = 0;

  constructor(algorithm: string, remainingBudget: number) {
    super();
    this.#hash = createHash(algorithm);
    this.#remainingBudget = remainingBudget;
  }

  override async init(size?: number): Promise<void> {
    if (size !== undefined && size > this.#remainingBudget)
      throw new RecordVerifyBudgetError(size);
    await super.init?.(size);
  }

  override async writeUint8Array(array: Uint8Array): Promise<void> {
    if (this.#bytes + array.length > this.#remainingBudget)
      throw new RecordVerifyBudgetError(this.#bytes + array.length);
    this.#hash.update(array);
    this.#bytes += array.length;
  }

  override async getData(): Promise<{
    readonly digest: string;
    readonly bytes: number;
  }> {
    return {
      digest: this.#hash.digest("base64url"),
      bytes: this.#bytes,
    };
  }
}

class RandomAccessZipReader extends Reader<undefined> {
  readonly #source: PrefixedByteSource;
  readonly #path: string;

  constructor(source: PrefixedByteSource, path: string) {
    super(undefined);
    this.#source = source;
    this.#path = path;
    this.size = source.size;
  }

  override async readUint8Array(
    index: number,
    length: number,
  ): Promise<Uint8Array> {
    const readBytes = Math.min(length, this.size - index);
    if (readBytes < 0)
      throw new ArtifactReaderFailure(
        "format",
        `ZIP archive is malformed: read at ${String(index)} extends beyond the ${String(this.size)}-byte archive`,
      );
    const bytes = await this.#source.readRange(index, readBytes);
    if (bytes.length !== readBytes)
      throw new ArtifactReaderFailure(
        "integrity",
        `ZIP source ended before its admitted extent: ${this.#path}`,
        { integrityCheck: "read-coverage" },
      );
    return bytes;
  }
}

const decodeUtf8 = (bytes: Uint8Array): string | null => {
  try {
    const text = UTF8_DECODER.decode(bytes);
    return text.startsWith("\uFEFF") ? text.slice(1) : text;
  } catch {
    return null;
  }
};

/** Parse RFC-822 headers (Core Metadata / WHEEL) with folded continuations. */
export const parseRfc822Headers = (
  text: string,
): { readonly headers: Map<string, string[]>; readonly body: string } => {
  const normalized = text.replace(/\r\n/gu, "\n").replace(/\r/gu, "\n");
  const lines = normalized.split("\n");
  const headers = new Map<string, string[]>();
  let currentKey: string | null = null;
  let bodyStart = lines.length;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    if (line === "") {
      bodyStart = index + 1;
      break;
    }
    if ((line.startsWith(" ") || line.startsWith("\t")) && currentKey !== null) {
      const list = headers.get(currentKey);
      if (list !== undefined && list.length > 0) {
        const last = list[list.length - 1]!;
        const continuation = line.startsWith("       |")
          ? line.slice(8)
          : line.trimStart();
        list[list.length - 1] = `${last}\n${continuation}`;
      }
      continue;
    }
    const colon = line.indexOf(":");
    if (colon <= 0) {
      currentKey = null;
      continue;
    }
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    currentKey = key;
    const existing = headers.get(key);
    if (existing === undefined) headers.set(key, [value]);
    else existing.push(value);
  }

  return {
    headers,
    body: lines.slice(bodyStart).join("\n"),
  };
};

const firstHeader = (headers: Map<string, string[]>, key: string): string | null => {
  const values = headers.get(key);
  if (values === undefined || values.length === 0) return null;
  return nonempty(values[0]);
};

const allHeaders = (headers: Map<string, string[]>, key: string): string[] => {
  const values = headers.get(key);
  if (values === undefined) return [];
  const out: string[] = [];
  for (const raw of values) {
    const value = nonempty(raw);
    if (value !== null) out.push(value);
  }
  return out;
};

const parseMetadataText = (text: string): NonNullable<PythonWheel["metadata"]> => {
  const { headers } = parseRfc822Headers(text);
  const projectUrls: NonNullable<PythonWheel["metadata"]>["project_urls"] = [];
  for (const raw of allHeaders(headers, "project-url")) {
    const comma = raw.indexOf(",");
    if (comma <= 0) continue;
    const label = nonempty(raw.slice(0, comma));
    const rawUrl = nonempty(raw.slice(comma + 1));
    if (label === null || rawUrl === null) continue;
    const redacted = redactRecordedTransportUrl(rawUrl);
    if (redacted.url === null) continue;
    projectUrls.push({
      label,
      url: redacted.url,
      url_credentials_redacted: redacted.url_credentials_redacted,
    });
  }
  const rawHomePage = firstHeader(headers, "home-page");
  const homePage = redactRecordedTransportUrl(rawHomePage);
  return {
    metadata_version: firstHeader(headers, "metadata-version"),
    name: firstHeader(headers, "name"),
    version: firstHeader(headers, "version"),
    summary: firstHeader(headers, "summary"),
    author: firstHeader(headers, "author"),
    author_email: firstHeader(headers, "author-email"),
    maintainer: firstHeader(headers, "maintainer"),
    license: firstHeader(headers, "license"),
    license_expression: firstHeader(headers, "license-expression"),
    requires_python: firstHeader(headers, "requires-python"),
    requires_dist: allHeaders(headers, "requires-dist"),
    provides_extra: allHeaders(headers, "provides-extra"),
    classifiers: allHeaders(headers, "classifier"),
    project_urls: projectUrls,
    home_page: homePage.url,
    home_page_credentials_redacted: homePage.url_credentials_redacted,
  };
};

const parseWheelTag = (raw: string): NonNullable<PythonWheel["wheel"]>["tags"][number] => {
  const parts = raw.split("-");
  if (parts.length !== 3)
    return { raw, python_tag: null, abi_tag: null, platform_tag: null };
  return {
    raw,
    python_tag: nonempty(parts[0]),
    abi_tag: nonempty(parts[1]),
    platform_tag: nonempty(parts[2]),
  };
};

const parseWheelFileText = (text: string): NonNullable<PythonWheel["wheel"]> => {
  const { headers } = parseRfc822Headers(text);
  const purelibRaw = firstHeader(headers, "root-is-purelib")?.toLowerCase();
  const rootIsPurelib =
    purelibRaw === "true" ? true : purelibRaw === "false" ? false : null;
  return {
    wheel_version: firstHeader(headers, "wheel-version"),
    generator: firstHeader(headers, "generator"),
    root_is_purelib: rootIsPurelib,
    tags: allHeaders(headers, "tag").map(parseWheelTag),
    build: firstHeader(headers, "build"),
  };
};

const parseEntryPointsText = (text: string): PythonWheel["entry_points"] => {
  const normalized = text.replace(/\r\n/gu, "\n").replace(/\r/gu, "\n");
  const entryPoints: PythonWheel["entry_points"] = [];
  let currentGroup: string | null = null;
  for (const rawLine of normalized.split("\n")) {
    const trimmed = rawLine.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";"))
      continue;
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      currentGroup = nonempty(trimmed.slice(1, -1));
      continue;
    }
    if (currentGroup === null) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const name = nonempty(trimmed.slice(0, eq));
    const value = nonempty(trimmed.slice(eq + 1));
    if (name !== null && value !== null)
      entryPoints.push({ group: currentGroup, name, value });
  }
  return entryPoints;
};

const parseTopLevelText = (text: string): string[] => {
  const normalized = text.replace(/\r\n/gu, "\n").replace(/\r/gu, "\n");
  const names: string[] = [];
  for (const rawLine of normalized.split("\n")) {
    const value = nonempty(rawLine);
    if (value !== null) names.push(value);
  }
  return names;
};

const parseDirectUrlJson = (
  text: string,
  limitations: string[],
): PythonWheel["direct_url"] => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    limitations.push("direct_url.json is not valid JSON.");
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    limitations.push("direct_url.json root is not a JSON object.");
    return null;
  }
  const record = parsed as Record<string, unknown>;
  const rawUrl = typeof record.url === "string" ? nonempty(record.url) : null;
  const redacted = redactRecordedTransportUrl(rawUrl);
  const vcsInfo =
    record.vcs_info !== null &&
    typeof record.vcs_info === "object" &&
    !Array.isArray(record.vcs_info)
      ? (record.vcs_info as Record<string, unknown>)
      : null;
  const dirInfo =
    record.dir_info !== null &&
    typeof record.dir_info === "object" &&
    !Array.isArray(record.dir_info)
      ? (record.dir_info as Record<string, unknown>)
      : null;
  return {
    url: redacted.url,
    url_credentials_redacted: redacted.url_credentials_redacted,
    vcs: vcsInfo !== null && typeof vcsInfo.vcs === "string" ? nonempty(vcsInfo.vcs) : null,
    commit_id:
      vcsInfo !== null && typeof vcsInfo.commit_id === "string"
        ? nonempty(vcsInfo.commit_id)
        : null,
    editable:
      dirInfo !== null && typeof dirInfo.editable === "boolean"
        ? dirInfo.editable
        : null,
  };
};

/** Parse one RFC-4180 CSV line used in PEP 376 RECORD files. */
export const parseRecordCsvLine = (line: string): string[] | null => {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;
  let index = 0;
  while (index < line.length) {
    const ch = line[index]!;
    if (inQuotes) {
      if (ch === '"') {
        if (line[index + 1] === '"') {
          current += '"';
          index += 2;
          continue;
        }
        inQuotes = false;
        index += 1;
        continue;
      }
      current += ch;
      index += 1;
      continue;
    }
    if (ch === '"' && current === "") {
      inQuotes = true;
      index += 1;
      continue;
    }
    if (ch === ",") {
      fields.push(current);
      current = "";
      index += 1;
      continue;
    }
    current += ch;
    index += 1;
  }
  if (inQuotes) return null;
  fields.push(current);
  return fields;
};

interface RecordRow {
  readonly path: string;
  readonly algorithm: string | null;
  readonly digest: string | null;
  readonly size: number | null;
  readonly malformedDetail?: string;
}

const parseRecordRows = (text: string): RecordRow[] => {
  const normalized = text.replace(/\r\n/gu, "\n").replace(/\r/gu, "\n");
  const rows: RecordRow[] = [];
  for (const rawLine of normalized.split("\n")) {
    if (rawLine.trim() === "") continue;
    const fields = parseRecordCsvLine(rawLine);
    if (fields === null || fields.length !== 3) {
      rows.push({
        path: nonempty(rawLine) ?? "<empty>",
        algorithm: null,
        digest: null,
        size: null,
        malformedDetail: "RECORD row does not contain 3 valid CSV columns.",
      });
      continue;
    }
    const path = pythonWheelLogicalPath(fields[0]!.trim());
    if (path === "") {
      rows.push({
        path: "<empty>",
        algorithm: null,
        digest: null,
        size: null,
        malformedDetail: "RECORD row has an empty file path.",
      });
      continue;
    }
    const hashField = fields[1]!.trim();
    const sizeField = fields[2]!.trim();
    let algorithm: string | null = null;
    let digest: string | null = null;
    if (hashField !== "") {
      const eq = hashField.indexOf("=");
      if (eq <= 0 || eq === hashField.length - 1) {
        rows.push({
          path,
          algorithm: null,
          digest: null,
          size: null,
          malformedDetail: `Malformed RECORD hash specification ${JSON.stringify(hashField)}.`,
        });
        continue;
      }
      algorithm = hashField.slice(0, eq).toLowerCase();
      digest = hashField.slice(eq + 1);
    }
    let size: number | null = null;
    if (sizeField !== "") {
      if (!/^[0-9]+$/u.test(sizeField)) {
        rows.push({
          path,
          algorithm,
          digest,
          size: null,
          malformedDetail: `Malformed RECORD byte size ${JSON.stringify(sizeField)}.`,
        });
        continue;
      }
      const parsedSize = Number(sizeField);
      if (!Number.isSafeInteger(parsedSize)) {
        rows.push({
          path,
          algorithm,
          digest,
          size: null,
          malformedDetail: `RECORD byte size exceeds safe integer range: ${sizeField}.`,
        });
        continue;
      }
      size = parsedSize;
    }
    rows.push({ path, algorithm, digest, size });
  }
  return rows;
};

const isSelfRecordPath = (distInfoDir: string, path: string): boolean =>
  path === `${distInfoDir}/RECORD` ||
  path === `${distInfoDir}/RECORD.jws` ||
  path === `${distInfoDir}/RECORD.p7s`;

interface IndexedFile {
  readonly entry: FileEntry;
  readonly sourceName: string;
  readonly path: string;
}

const emptyRecordSummary = (
  present: boolean,
  status: PythonWheel["record"]["verification_status"],
): PythonWheel["record"] => ({
  present,
  entry_count: 0,
  verified_count: 0,
  mismatched_count: 0,
  missing_from_archive_count: 0,
  unrecorded_archive_count: 0,
  unsupported_algorithm_count: 0,
  unhashed_count: 0,
  skipped_budget_count: 0,
  verification_status: status,
  anomalies: [],
});

/** Decode one bounded Python .whl distribution without installing or executing code. */
export const parsePythonWheel = async (
  source: PrefixedByteSource,
  artifact: { path: string; sha256: string; bytes: number },
  input: InspectPythonWheelInput,
  signal?: AbortSignal,
): Promise<PythonWheel> => {
  if (source.size !== artifact.bytes)
    throw malformedInput(
      PYTHON_WHEEL_FORMAT,
      "Selected artifact length disagrees with the retained bytes.",
    );
  if (!hasZipSignature(source.prefix))
    throw malformedInput(
      PYTHON_WHEEL_FORMAT,
      "Selected file is not a ZIP archive (Python .whl).",
    );
  const reader = new ZipReader(
    new RandomAccessZipReader(source, artifact.path),
    ZIP_READER_OPTIONS,
  );
  const readLocalRange = (at: number, length: number): Promise<Uint8Array> =>
    source.readRange(at, length);
  const limitations: string[] = [...BASE_LIMITATIONS];
  const zipAbort = signal === undefined ? undefined : new AbortController();
  const zipSignal = zipAbort?.signal;
  const onAbort = () =>
    zipAbort?.abort(
      new ArtifactReaderFailure("cancelled", "Artifact read cancelled", {
        cause: signal?.reason,
      }),
    );
  if (signal?.aborted) onAbort();
  else signal?.addEventListener("abort", onAbort, { once: true });

  try {
    assertArtifactReadActive(signal);
    const entries: Entry[] = [];
    try {
      for await (const entry of reader.getEntriesGenerator({
        decodeText: decodeZipEntryText,
      })) {
        assertArtifactReadActive(signal);
        if (entries.length >= input.max_entries)
          throw decodeLimit(
            PYTHON_WHEEL_FORMAT,
            `Python wheel ZIP exceeds the ${String(input.max_entries)}-entry budget.`,
            {
              name: "max_entries",
              maximum: input.max_entries,
              required: entries.length + 1,
            },
          );
        entries.push(entry);
      }
    } catch (cause: unknown) {
      return wrapZipFailure(cause);
    }
    assertArtifactReadActive(signal);

    const directoryOffset = reader.directoryOffset;
    const listing = zipListingCoverage(
      directoryOffset === undefined
        ? undefined
        : await accountZipMemberRegion(
            entries.map((entry) => ({
              offset: entry.offset,
              compressedSize: entry.compressedSize,
              uncompressedSize: entry.uncompressedSize,
              crc32: entry.crc32,
              zip64: entry.zip64,
              dataDescriptor: entry.bitFlag?.dataDescriptor ?? false,
            })),
            directoryOffset,
            readLocalRange,
          ),
    );
    limitations.push(...listing.limitations);

    const files: IndexedFile[] = [];
    const contents: PythonWheel["contents"] = [];
    const nativeExtensions: string[] = [];
    const filesByPath = new Map<string, IndexedFile[]>();

    for (const entry of entries) {
      if (entry.directory) continue;
      if (!asFileEntry(entry)) continue;
      const sourceName = zipEntryPath(entry);
      const path = pythonWheelLogicalPath(sourceName);
      if (path === "") continue;
      for (const limitation of zipEntryNameLimitations(entry))
        limitations.push(
          `ZIP member ${JSON.stringify(sourceName)}: ${limitation}`,
        );
      const role = pythonWheelEntryRole(path);
      const indexed: IndexedFile = { entry, sourceName, path };
      files.push(indexed);
      const existing = filesByPath.get(path);
      if (existing === undefined) filesByPath.set(path, [indexed]);
      else existing.push(indexed);
      if (role === "native-extension") nativeExtensions.push(path);
      contents.push({
        name: sourceName,
        path,
        uncompressed_size: zipSize(entry.uncompressedSize),
        compressed_size: zipSize(entry.compressedSize),
        role,
        encrypted: entry.encrypted === true,
      });
    }

    // Check duplicate archive paths.
    for (const [path, matches] of filesByPath.entries()) {
      if (matches.length > 1)
        limitations.push(
          `Archive contains ${String(matches.length)} duplicate entries for logical path ${JSON.stringify(path)}.`,
        );
    }

    // Discover root *.dist-info directories.
    const distInfoDirs = new Set<string>();
    for (const file of files) {
      const slash = file.path.indexOf("/");
      if (slash > 0) {
        const head = file.path.slice(0, slash);
        if (head.endsWith(".dist-info")) distInfoDirs.add(head);
      }
    }

    if (distInfoDirs.size === 0) {
      limitations.push(PYTHON_WHEEL_LIMITATIONS.noDistInfo);
      return {
        artifact: {
          path: artifact.path,
          sha256: artifact.sha256,
          bytes: artifact.bytes,
        },
        dist_info: null,
        metadata: null,
        wheel: null,
        entry_points: [],
        top_level: [],
        direct_url: null,
        record: emptyRecordSummary(false, "unavailable"),
        native_extensions: nativeExtensions,
        contents,
        coverage: {
          status: listing.status,
          entries: contents.length,
          examined_metadata_bytes: 0,
          verified_record_bytes: 0,
        },
        limitations,
      };
    }

    if (distInfoDirs.size > 1) {
      limitations.push(PYTHON_WHEEL_LIMITATIONS.ambiguousDistInfo);
      return {
        artifact: {
          path: artifact.path,
          sha256: artifact.sha256,
          bytes: artifact.bytes,
        },
        dist_info: null,
        metadata: null,
        wheel: null,
        entry_points: [],
        top_level: [],
        direct_url: null,
        record: emptyRecordSummary(false, "unavailable"),
        native_extensions: nativeExtensions,
        contents,
        coverage: {
          status: listing.status,
          entries: contents.length,
          examined_metadata_bytes: 0,
          verified_record_bytes: 0,
        },
        limitations,
      };
    }

    const distInfoDir = [...distInfoDirs][0]!;
    const selectDistInfoFile = (filename: string): IndexedFile | undefined => {
      const target = `${distInfoDir}/${filename}`;
      const matches = filesByPath.get(target);
      if (matches === undefined || matches.length === 0) return undefined;
      if (matches.length > 1) {
        limitations.push(
          `Multiple archive members match ${JSON.stringify(target)}; that metadata file was not decoded.`,
        );
        return undefined;
      }
      return matches[0];
    };

    const metadataFile = selectDistInfoFile("METADATA");
    const wheelFile = selectDistInfoFile("WHEEL");
    const recordFile = selectDistInfoFile("RECORD");
    const entryPointsFile = selectDistInfoFile("entry_points.txt");
    const topLevelFile = selectDistInfoFile("top_level.txt");
    const directUrlFile = selectDistInfoFile("direct_url.json");

    let examinedMetadataBytes = 0;
    const readMetadataText = async (
      file: IndexedFile | undefined,
      label: string,
    ): Promise<string | null> => {
      if (file === undefined) return null;
      if (file.entry.encrypted) {
        limitations.push(
          `${label} (${JSON.stringify(file.path)}) is encrypted and was not extracted.`,
        );
        return null;
      }
      const remaining = input.max_metadata_bytes - examinedMetadataBytes;
      const exceeded = (required: number) =>
        decodeLimit(
          PYTHON_WHEEL_FORMAT,
          `Decoded *.dist-info metadata exceeds the ${String(input.max_metadata_bytes)}-byte budget while reading ${label}.`,
          {
            name: "max_metadata_bytes",
            maximum: input.max_metadata_bytes,
            required: examinedMetadataBytes + required,
          },
        );
      const declared = zipSize(file.entry.uncompressedSize);
      if (declared !== null && declared > remaining) throw exceeded(declared);
      let bytes: Uint8Array;
      try {
        bytes = await file.entry.getData(
          new BoundedUint8ArrayWriter(remaining, exceeded),
          {
            checkSignature: true,
            ...(zipSignal === undefined ? {} : { signal: zipSignal }),
          },
        );
      } catch (cause: unknown) {
        return wrapZipFailure(cause, file.entry.compressionMethod);
      }
      examinedMetadataBytes += bytes.length;
      const text = decodeUtf8(bytes);
      if (text === null) {
        limitations.push(`${label} (${JSON.stringify(file.path)}) is not valid UTF-8 text.`);
        return null;
      }
      return text;
    };

    const metadataText = await readMetadataText(metadataFile, "METADATA");
    const wheelText = await readMetadataText(wheelFile, "WHEEL");
    const entryPointsText = await readMetadataText(
      entryPointsFile,
      "entry_points.txt",
    );
    const topLevelText = await readMetadataText(topLevelFile, "top_level.txt");
    const directUrlText = await readMetadataText(
      directUrlFile,
      "direct_url.json",
    );
    const recordText = await readMetadataText(recordFile, "RECORD");

    if (metadataFile === undefined)
      limitations.push(`No ${distInfoDir}/METADATA file was present in the wheel.`);
    if (wheelFile === undefined)
      limitations.push(`No ${distInfoDir}/WHEEL file was present in the wheel.`);

    const metadata =
      metadataText === null ? null : parseMetadataText(metadataText);
    const wheel = wheelText === null ? null : parseWheelFileText(wheelText);
    const entryPoints =
      entryPointsText === null ? [] : parseEntryPointsText(entryPointsText);
    const topLevel =
      topLevelText === null ? [] : parseTopLevelText(topLevelText);
    const directUrl =
      directUrlText === null
        ? null
        : parseDirectUrlJson(directUrlText, limitations);

    let verifiedRecordBytes = 0;
    let recordResult: PythonWheel["record"];

    if (recordFile === undefined || recordText === null) {
      if (recordFile === undefined)
        limitations.push(`No ${distInfoDir}/RECORD file was present in the wheel.`);
      recordResult = emptyRecordSummary(false, "unavailable");
    } else {
      const rows = parseRecordRows(recordText);
      const seenPaths = new Set<string>();
      const anomalies: PythonWheel["record"]["anomalies"] = [];
      let verifiedCount = 0;
      let mismatchedCount = 0;
      let missingFromArchiveCount = 0;
      let unsupportedAlgorithmCount = 0;
      let unhashedCount = 0;
      let skippedBudgetCount = 0;

      if (!input.verify_record)
        limitations.push(PYTHON_WHEEL_LIMITATIONS.recordSkipped);

      for (const row of rows) {
        assertArtifactReadActive(signal);
        if (row.malformedDetail !== undefined) {
          mismatchedCount += 1;
          anomalies.push({
            path: row.path,
            kind: "malformed-row",
            detail: row.malformedDetail,
          });
          continue;
        }
        if (seenPaths.has(row.path)) {
          mismatchedCount += 1;
          anomalies.push({
            path: row.path,
            kind: "duplicate-record-entry",
            detail: `RECORD lists ${JSON.stringify(row.path)} more than once.`,
          });
          continue;
        }
        seenPaths.add(row.path);

        const archiveMatches = filesByPath.get(row.path);
        if (archiveMatches === undefined || archiveMatches.length === 0) {
          missingFromArchiveCount += 1;
          anomalies.push({
            path: row.path,
            kind: "missing-in-archive",
            declared_hash: row.digest,
            declared_size: row.size,
            detail: `RECORD entry ${JSON.stringify(row.path)} is absent from the ZIP archive.`,
          });
          continue;
        }

        if (archiveMatches.length > 1) {
          mismatchedCount += 1;
          anomalies.push({
            path: row.path,
            kind: "duplicate-record-entry",
            detail: `ZIP archive contains ${String(archiveMatches.length)} members for RECORD path ${JSON.stringify(row.path)}.`,
          });
          continue;
        }

        const member = archiveMatches[0]!;
        if (row.algorithm === null && row.digest === null && row.size === null) {
          unhashedCount += 1;
          if (!isSelfRecordPath(distInfoDir, row.path))
            limitations.push(
              `RECORD entry ${JSON.stringify(row.path)} omits both hash and size.`,
            );
          continue;
        }

        if (!input.verify_record) continue;

        if (member.entry.encrypted) {
          anomalies.push({
            path: row.path,
            kind: "encrypted-member",
            detail: `ZIP member ${JSON.stringify(row.path)} is encrypted and could not be hashed against RECORD.`,
          });
          continue;
        }

        if (row.algorithm !== null && !SUPPORTED_RECORD_ALGORITHMS.has(row.algorithm)) {
          unsupportedAlgorithmCount += 1;
          anomalies.push({
            path: row.path,
            kind: "unsupported-algorithm",
            algorithm: row.algorithm,
            declared_hash: row.digest,
            declared_size: row.size,
            detail: `RECORD hash algorithm ${JSON.stringify(row.algorithm)} is not supported (supported: sha256, sha384, sha512).`,
          });
          continue;
        }

        const hashAlgorithm = row.algorithm ?? "sha256";
        const remainingBudget = input.max_record_verify_bytes - verifiedRecordBytes;
        const declaredMemberSize = zipSize(member.entry.uncompressedSize);
        if (declaredMemberSize !== null && declaredMemberSize > remainingBudget) {
          skippedBudgetCount += 1;
          anomalies.push({
            path: row.path,
            kind: "budget-exceeded",
            declared_size: row.size,
            observed_size: declaredMemberSize,
            detail: `Member exceeds remaining max_record_verify_bytes budget (${String(remainingBudget)} bytes remaining).`,
          });
          continue;
        }

        let measured: { readonly digest: string; readonly bytes: number };
        try {
          measured = await member.entry.getData(
            new BoundedHashWriter(hashAlgorithm, remainingBudget),
            {
              checkSignature: true,
              ...(zipSignal === undefined ? {} : { signal: zipSignal }),
            },
          );
        } catch (cause: unknown) {
          if (cause instanceof RecordVerifyBudgetError) {
            skippedBudgetCount += 1;
            anomalies.push({
              path: row.path,
              kind: "budget-exceeded",
              declared_size: row.size,
              detail: `Member decompressed past remaining max_record_verify_bytes budget (${String(remainingBudget)} bytes remaining).`,
            });
            continue;
          }
          return wrapZipFailure(cause, member.entry.compressionMethod);
        }

        verifiedRecordBytes += measured.bytes;
        let rowMismatched = false;
        if (row.size !== null && measured.bytes !== row.size) {
          rowMismatched = true;
          anomalies.push({
            path: row.path,
            kind: "size-mismatch",
            declared_size: row.size,
            observed_size: measured.bytes,
            detail: `RECORD declares ${String(row.size)} bytes for ${JSON.stringify(row.path)}, observed ${String(measured.bytes)} bytes.`,
          });
        }
        if (row.algorithm !== null && row.digest !== null) {
          const normalizedDeclared = row.digest.replace(/=+$/u, "");
          if (measured.digest !== normalizedDeclared) {
            rowMismatched = true;
            anomalies.push({
              path: row.path,
              kind: "hash-mismatch",
              algorithm: row.algorithm,
              declared_hash: row.digest,
              observed_hash: measured.digest,
              detail: `RECORD ${row.algorithm} digest mismatch for ${JSON.stringify(row.path)}.`,
            });
          }
        }
        if (rowMismatched) mismatchedCount += 1;
        else verifiedCount += 1;
      }

      // Report archive files missing from RECORD.
      let unrecordedArchiveCount = 0;
      for (const path of filesByPath.keys()) {
        if (seenPaths.has(path)) continue;
        unrecordedArchiveCount += 1;
        anomalies.push({
          path,
          kind: "unrecorded-in-record",
          detail: `ZIP member ${JSON.stringify(path)} is present in the archive but omitted from RECORD.`,
        });
      }

      let verificationStatus: PythonWheel["record"]["verification_status"];
      if (!input.verify_record) {
        verificationStatus =
          mismatchedCount > 0 ||
          missingFromArchiveCount > 0 ||
          unrecordedArchiveCount > 0
            ? "mismatched"
            : "skipped";
      } else if (
        mismatchedCount > 0 ||
        missingFromArchiveCount > 0 ||
        unrecordedArchiveCount > 0
      ) {
        verificationStatus = "mismatched";
      } else if (
        unsupportedAlgorithmCount > 0 ||
        skippedBudgetCount > 0 ||
        anomalies.some((item) => item.kind === "encrypted-member")
      ) {
        verificationStatus = "partial";
      } else {
        verificationStatus = "verified";
      }

      if (skippedBudgetCount > 0)
        limitations.push(
          `${String(skippedBudgetCount)} RECORD member(s) were not hashed because max_record_verify_bytes (${String(input.max_record_verify_bytes)}) was exhausted.`,
        );

      recordResult = {
        present: true,
        entry_count: rows.length,
        verified_count: verifiedCount,
        mismatched_count: mismatchedCount,
        missing_from_archive_count: missingFromArchiveCount,
        unrecorded_archive_count: unrecordedArchiveCount,
        unsupported_algorithm_count: unsupportedAlgorithmCount,
        unhashed_count: unhashedCount,
        skipped_budget_count: skippedBudgetCount,
        verification_status: verificationStatus,
        anomalies,
      };
    }

    return {
      artifact: {
        path: artifact.path,
        sha256: artifact.sha256,
        bytes: artifact.bytes,
      },
      dist_info: {
        directory: distInfoDir,
        metadata_path: metadataFile?.path ?? null,
        wheel_path: wheelFile?.path ?? null,
        record_path: recordFile?.path ?? null,
        entry_points_path: entryPointsFile?.path ?? null,
        top_level_path: topLevelFile?.path ?? null,
        direct_url_path: directUrlFile?.path ?? null,
      },
      metadata,
      wheel,
      entry_points: entryPoints,
      top_level: topLevel,
      direct_url: directUrl,
      record: recordResult,
      native_extensions: nativeExtensions,
      contents,
      coverage: {
        status: listing.status,
        entries: contents.length,
        examined_metadata_bytes: examinedMetadataBytes,
        verified_record_bytes: verifiedRecordBytes,
      },
      limitations,
    };
  } finally {
    signal?.removeEventListener("abort", onAbort);
    await reader.close().catch(() => undefined);
  }
};
