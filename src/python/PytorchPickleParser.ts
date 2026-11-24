import {
  Reader,
  Uint8ArrayWriter,
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
  PYTORCH_PICKLE_FORMAT,
  type InspectPytorchCheckpointInput,
  type PytorchCheckpoint,
} from "../domain/python/pytorchPickle.js";
import { accountZipMemberRegion } from "../domain/zip/zipMemberRegion.js";
import { hasZipSignature } from "../domain/zipPackageFormat.js";
import {
  ArtifactReaderFailure,
  assertArtifactReadActive,
  decodeZipEntryText,
  typedZipFailure,
  ZIP_READER_OPTIONS,
  zipEntryPath,
  zipListingCoverage,
} from "../resources/index.js";
import { decodePickleStream } from "./PickleOpcodeDecoder.js";

const BASE_LIMITATIONS = [
  "This workflow decodes PyTorch ZIP archives and Python pickle opcodes symbolically without executing callables, invoking Python, or loading tensors into memory.",
  "Flagged globals identify known code-execution or privileged imports; absence of flagged globals does not prove that unpickling the file is safe.",
] as const;

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });

const zipSize = (value: number | undefined): number | null =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : null;

const asFileEntry = (entry: Entry): entry is FileEntry =>
  !entry.directory && typeof entry.getData === "function";

const normalizePath = (name: string): string =>
  name.replaceAll("\\", "/").replace(/^(?:\.\/)+/u, "");

const wrapZipFailure = (cause: unknown, compressionMethod?: number): never => {
  if (cause instanceof ParseFailureError) throw cause;
  const typed = typedZipFailure(cause, compressionMethod);
  if (typed instanceof ArtifactReaderFailure && typed.reason === "limit")
    throw typed;
  if (typed instanceof ArtifactReaderFailure && typed.reason === "unavailable")
    throw unsupportedInput(
      PYTORCH_PICKLE_FORMAT,
      `PyTorch ZIP archive uses an unsupported layout: ${typed.message}`,
      { cause: typed },
    );
  if (typed instanceof ArtifactReaderFailure && typed.reason === "format")
    throw malformedInput(PYTORCH_PICKLE_FORMAT, typed.message, { cause: typed });
  throw cause;
};

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
        `ZIP archive is malformed: read at ${String(index)} extends beyond ${String(this.size)} bytes`,
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

const readBoundedEntry = async (
  entry: FileEntry,
  maximum: number,
  label: string,
  signal?: AbortSignal,
): Promise<Uint8Array> => {
  const exceeded = (required: number) =>
    decodeLimit(
      PYTORCH_PICKLE_FORMAT,
      `${label} exceeds the ${String(maximum)}-byte max_pickle_bytes budget.`,
      { name: "max_pickle_bytes", maximum, required },
    );
  const declared = zipSize(entry.uncompressedSize);
  if (declared !== null && declared > maximum) throw exceeded(declared);
  try {
    return await entry.getData(new BoundedUint8ArrayWriter(maximum, exceeded), {
      checkSignature: true,
      ...(signal === undefined ? {} : { signal }),
    });
  } catch (cause: unknown) {
    return wrapZipFailure(cause, entry.compressionMethod);
  }
};

const parseRawPickle = async (
  source: PrefixedByteSource,
  artifact: { path: string; sha256: string; bytes: number },
  input: InspectPytorchCheckpointInput,
  signal?: AbortSignal,
): Promise<PytorchCheckpoint> => {
  assertArtifactReadActive(signal);
  if (source.size > input.max_pickle_bytes)
    throw decodeLimit(
      PYTORCH_PICKLE_FORMAT,
      `Raw pickle file (${String(source.size)} bytes) exceeds max_pickle_bytes (${String(input.max_pickle_bytes)}).`,
      {
        name: "max_pickle_bytes",
        maximum: input.max_pickle_bytes,
        required: source.size,
      },
    );
  const bytes = await source.readRange(0, source.size);
  const decoded = decodePickleStream(bytes, input.max_opcodes);
  const limitations = [...BASE_LIMITATIONS, ...decoded.limitations];
  const tensors = decoded.tensors.map(({ name, info }) => ({
    name,
    ...info,
    archive_member: null,
    archive_bytes: null,
  }));
  return {
    artifact: {
      path: artifact.path,
      sha256: artifact.sha256,
      bytes: artifact.bytes,
    },
    container_format: "raw-pickle",
    archive: null,
    pickle: {
      protocol: decoded.protocol,
      bytes: bytes.length,
      opcodes_decoded: decoded.opcodes_decoded,
      truncated: decoded.truncated,
      terminated_with_stop: decoded.terminated_with_stop,
      reduce_count: decoded.reduce_count,
      build_count: decoded.build_count,
      newobj_count: decoded.newobj_count,
      persistent_load_count: decoded.persistent_load_count,
      globals: decoded.globals,
      flagged_globals: decoded.flagged_globals,
      top_level_keys: decoded.top_level_keys,
    },
    tensors,
    coverage: {
      status: decoded.truncated ? "partial" : "complete",
      entries: 1,
      examined_pickle_bytes: bytes.length,
      opcodes_decoded: decoded.opcodes_decoded,
    },
    limitations,
  };
};

/** Inspect a PyTorch ZIP checkpoint (.pt/.pth/.ckpt) or standalone pickle (.pkl). */
export const parsePytorchCheckpoint = async (
  source: PrefixedByteSource,
  artifact: { path: string; sha256: string; bytes: number },
  input: InspectPytorchCheckpointInput,
  signal?: AbortSignal,
): Promise<PytorchCheckpoint> => {
  if (source.size !== artifact.bytes)
    throw malformedInput(
      PYTORCH_PICKLE_FORMAT,
      "Selected artifact length disagrees with the retained bytes.",
    );
  if (!hasZipSignature(source.prefix))
    return parseRawPickle(source, artifact, input, signal);

  const reader = new ZipReader(
    new RandomAccessZipReader(source, artifact.path),
    ZIP_READER_OPTIONS,
  );
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
            PYTORCH_PICKLE_FORMAT,
            `PyTorch ZIP archive exceeds max_entries (${String(input.max_entries)}).`,
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
            (at, length) => source.readRange(at, length),
          ),
    );
    limitations.push(...listing.limitations);

    const files: { readonly entry: FileEntry; readonly path: string }[] = [];
    for (const entry of entries) {
      if (!asFileEntry(entry)) continue;
      const path = normalizePath(zipEntryPath(entry));
      if (path !== "") files.push({ entry, path });
    }

    const pickleCandidates = files.filter(
      (f) => f.path === "data.pkl" || f.path.endsWith("/data.pkl"),
    );
    if (pickleCandidates.length === 0)
      throw malformedInput(
        PYTORCH_PICKLE_FORMAT,
        "ZIP archive does not contain a PyTorch data.pkl member.",
      );
    if (pickleCandidates.length > 1)
      limitations.push(
        `Archive contains ${String(pickleCandidates.length)} data.pkl members; inspected the first (${pickleCandidates[0]!.path}).`,
      );

    const pickleFile = pickleCandidates[0]!;
    const slash = pickleFile.path.lastIndexOf("/");
    const prefix = slash === -1 ? null : pickleFile.path.slice(0, slash);
    const lookupInPrefix = (leaf: string) => {
      const target = prefix === null ? leaf : `${prefix}/${leaf}`;
      return files.find((f) => f.path === target);
    };

    const versionFile = lookupInPrefix("version");
    const byteorderFile = lookupInPrefix("byteorder");
    let versionText: string | null = null;
    let byteorderText: string | null = null;
    if (versionFile !== undefined && !versionFile.entry.encrypted) {
      const vb = await readBoundedEntry(versionFile.entry, 1024, "version", zipSignal);
      versionText = UTF8_DECODER.decode(vb).trim() || null;
    }
    if (byteorderFile !== undefined && !byteorderFile.entry.encrypted) {
      const bb = await readBoundedEntry(byteorderFile.entry, 1024, "byteorder", zipSignal);
      byteorderText = UTF8_DECODER.decode(bb).trim() || null;
    }

    const dataDirPrefix = prefix === null ? "data/" : `${prefix}/data/`;
    const storages: NonNullable<PytorchCheckpoint["archive"]>["storages"] = [];
    const storageByKey = new Map<
      string,
      NonNullable<PytorchCheckpoint["archive"]>["storages"][number]
    >();
    for (const file of files) {
      if (!file.path.startsWith(dataDirPrefix)) continue;
      const key = file.path.slice(dataDirPrefix.length);
      if (key === "") continue;
      const storage = {
        key,
        archive_member: file.path,
        uncompressed_size: zipSize(file.entry.uncompressedSize),
        compressed_size: zipSize(file.entry.compressedSize),
      };
      storages.push(storage);
      storageByKey.set(key, storage);
    }

    if (pickleFile.entry.encrypted)
      throw unsupportedInput(
        PYTORCH_PICKLE_FORMAT,
        `PyTorch pickle member ${JSON.stringify(pickleFile.path)} is encrypted.`,
      );

    const pickleBytes = await readBoundedEntry(
      pickleFile.entry,
      input.max_pickle_bytes,
      pickleFile.path,
      zipSignal,
    );
    const decoded = decodePickleStream(pickleBytes, input.max_opcodes);
    limitations.push(...decoded.limitations);

    const tensors = decoded.tensors.map(({ name, info }) => {
      const matched =
        info.storage_key !== null ? storageByKey.get(info.storage_key) : undefined;
      return {
        name,
        ...info,
        archive_member: matched?.archive_member ?? null,
        archive_bytes: matched?.uncompressed_size ?? null,
      };
    });

    const coverageStatus = decoded.truncated ? "partial" : listing.status;

    return {
      artifact: {
        path: artifact.path,
        sha256: artifact.sha256,
        bytes: artifact.bytes,
      },
      container_format: "pytorch-zip",
      archive: {
        prefix,
        pickle_member: pickleFile.path,
        version: versionText,
        byteorder: byteorderText,
        entry_count: files.length,
        storages,
      },
      pickle: {
        protocol: decoded.protocol,
        bytes: pickleBytes.length,
        opcodes_decoded: decoded.opcodes_decoded,
        truncated: decoded.truncated,
        terminated_with_stop: decoded.terminated_with_stop,
        reduce_count: decoded.reduce_count,
        build_count: decoded.build_count,
        newobj_count: decoded.newobj_count,
        persistent_load_count: decoded.persistent_load_count,
        globals: decoded.globals,
        flagged_globals: decoded.flagged_globals,
        top_level_keys: decoded.top_level_keys,
      },
      tensors,
      coverage: {
        status: coverageStatus,
        entries: files.length,
        examined_pickle_bytes: pickleBytes.length,
        opcodes_decoded: decoded.opcodes_decoded,
      },
      limitations,
    };
  } finally {
    signal?.removeEventListener("abort", onAbort);
    await reader.close().catch(() => undefined);
  }
};
