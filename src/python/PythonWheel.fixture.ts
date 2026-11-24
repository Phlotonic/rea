import { createHash } from "node:crypto";
import { BlobReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";

export interface WheelFixtureFile {
  readonly name: string;
  readonly content: string | Uint8Array;
}

const toBytes = (content: string | Uint8Array): Uint8Array =>
  typeof content === "string" ? new TextEncoder().encode(content) : content;

export const recordHash = (
  content: string | Uint8Array,
  algorithm: "sha256" | "sha384" | "sha512" = "sha256",
): string => {
  const bytes = toBytes(content);
  const digest = createHash(algorithm).update(bytes).digest("base64url");
  return `${algorithm}=${digest}`;
};

/** Build a real ZIP-encoded Python .whl buffer in memory for deterministic tests. */
export const buildPythonWheelFixture = async (
  files: readonly WheelFixtureFile[],
): Promise<Uint8Array> => {
  const writer = new Uint8ArrayWriter();
  const zip = new ZipWriter(writer, { bufferedWrite: true });
  for (const file of files) {
    const bytes = toBytes(file.content);
    await zip.add(file.name, new BlobReader(new Blob([bytes])));
  }
  await zip.close();
  return writer.getData();
};

/** Build a valid pure-Python wheel with METADATA, WHEEL, entry_points, top_level, and verified RECORD. */
export const buildStandardWheelFixture = async (options?: {
  readonly distInfo?: string;
  readonly tamperInitPy?: boolean;
  readonly extraUnrecorded?: boolean;
  readonly includeNativeExt?: boolean;
}): Promise<Uint8Array> => {
  const distInfo = options?.distInfo ?? "demo_pkg-1.2.3.dist-info";
  const initBytes = new TextEncoder().encode('__version__ = "1.2.3"\n');
  const metadataText = [
    "Metadata-Version: 2.4",
    "Name: demo-pkg",
    "Version: 1.2.3",
    "Summary: Demo Python wheel fixture",
    "Author: REA Maintainers",
    "Author-email: maintainers@example.com",
    "License-Expression: MIT",
    "Requires-Python: >=3.10",
    "Requires-Dist: httpx>=0.27",
    "Requires-Dist: pytest>=8.0; extra == 'dev'",
    "Provides-Extra: dev",
    "Classifier: Programming Language :: Python :: 3",
    "Home-page: https://user:secret@example.com/demo-pkg",
    "Project-URL: Source, https://token:pass@github.com/example/demo-pkg",
    "",
    "Long description body.",
  ].join("\n");
  const wheelText = [
    "Wheel-Version: 1.0",
    "Generator: hatchling 1.25.0",
    `Root-Is-Purelib: ${options?.includeNativeExt ? "false" : "true"}`,
    options?.includeNativeExt
      ? "Tag: cp312-cp312-manylinux_2_17_x86_64"
      : "Tag: py3-none-any",
    "",
  ].join("\n");
  const entryPointsText = [
    "[console_scripts]",
    "demo-cli = demo_pkg.cli:main",
    "",
    "[pytest11]",
    "demo_plugin = demo_pkg.plugin",
    "",
  ].join("\n");
  const topLevelText = "demo_pkg\n";
  const directUrlText = JSON.stringify({
    url: "https://user:token@github.com/example/demo-pkg.git",
    vcs_info: { vcs: "git", commit_id: "abcdef1234567890" },
  });

  const payloadFiles: WheelFixtureFile[] = [
    { name: "demo_pkg/__init__.py", content: initBytes },
    { name: "demo_pkg/py.typed", content: "" },
    ...(options?.includeNativeExt
      ? [
          {
            name: "demo_pkg/_native.cpython-312-x86_64-linux-gnu.so",
            content: new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
          },
        ]
      : []),
    { name: `${distInfo}/METADATA`, content: metadataText },
    { name: `${distInfo}/WHEEL`, content: wheelText },
    { name: `${distInfo}/entry_points.txt`, content: entryPointsText },
    { name: `${distInfo}/top_level.txt`, content: topLevelText },
    { name: `${distInfo}/direct_url.json`, content: directUrlText },
  ];

  const recordLines = payloadFiles.map((file) => {
    const bytes = toBytes(file.content);
    return `${file.name},${recordHash(bytes, "sha256")},${String(bytes.length)}`;
  });
  recordLines.push(`${distInfo}/RECORD,,`);
  const recordText = `${recordLines.join("\n")}\n`;

  const finalFiles: WheelFixtureFile[] = payloadFiles.map((file) =>
    options?.tamperInitPy && file.name === "demo_pkg/__init__.py"
      ? { name: file.name, content: '__version__ = "9.9.9"\n' }
      : file,
  );
  finalFiles.push({ name: `${distInfo}/RECORD`, content: recordText });
  if (options?.extraUnrecorded) {
    finalFiles.push({
      name: "demo_pkg/sneaky.py",
      content: "print('unrecorded')\n",
    });
  }

  return buildPythonWheelFixture(finalFiles);
};
