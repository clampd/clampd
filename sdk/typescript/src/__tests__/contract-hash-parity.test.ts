/**
 * Cross-language parity vectors for {@link contractHash}.
 *
 * The same input set + expected hex strings live in:
 *   - services/crates/ag-common/src/contract_hash.rs (parity_vectors fn)
 *   - sdk/python/tests/test_contract_hash_parity.py
 *
 * **DO NOT** update a hex string here in isolation. If a hash changes for
 * ONE implementation, the canonicalisation has drifted — investigate, do
 * not paper over it. All three implementations must agree byte-for-byte.
 *
 * When adding a vector: compute the hash in all three SDKs, verify they
 * match, then encode it in all three test files.
 */
import { describe, expect, it } from "vitest";
import { contractHash } from "../contract-hash.js";

interface Vector {
  label: string;
  name: string;
  description: string;
  parameters: object;
  expected: string;
}

const PARITY_VECTORS: Vector[] = [
  {
    label: "V1_simple_sql",
    name: "db.query",
    description: "Run a test query against the warehouse",
    parameters: {
      type: "object",
      properties: { sql: { type: "string" } },
      required: ["sql"],
    },
    expected:
      "972f2f0a904ff55ccc836c4667554b0857203f3f95ab43c0a681c851b2c77514",
  },
  {
    label: "V2_empty",
    name: "Bash",
    description: "",
    parameters: {},
    expected:
      "9fbfcf9a33c1b0736670b423c4d829feba026b6da5b30fa43fb8e184fccebe4b",
  },
  {
    label: "V3_nested_required",
    name: "fs.move",
    description: "Move a file to a new path",
    parameters: {
      type: "object",
      properties: {
        src: { type: "string" },
        dst: { type: "string" },
        options: {
          type: "object",
          properties: {
            overwrite: { type: "boolean", default: false },
          },
        },
      },
      required: ["src", "dst"],
    },
    expected:
      "8e60f85a924bde9f6a36792f594c78b30b9a4f230c6436ab1cd9d910811d1bf2",
  },
  {
    label: "V4_unicode",
    name: "comms.email",
    description: "Send an email — supports é, ñ, 漢字, 🚀",
    parameters: {
      type: "object",
      properties: { to: { type: "string", format: "email" } },
    },
    expected:
      "8d45eb20f59a49910265bcfe3ed32aa0d337c48f17355f95d17a3c3e8b9bcc23",
  },
  {
    label: "V5_special_chars",
    name: "fs.write",
    description: "Write content to a file",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string" },
        content: {
          type: "string",
          description:
            'Body text. May contain "quotes" and \\ backslashes and \nnewlines.',
        },
      },
    },
    expected:
      "9f02aa46ccc926a8e54feccc99b1c1059bce8aa5b5e4bfdb4e6c86e60cd885d1",
  },
  {
    label: "V6_arrays",
    name: "search.batch",
    description: "Batch keyword search",
    parameters: {
      type: "object",
      properties: {
        queries: { type: "array", items: { type: "string" }, minItems: 1 },
        tags: { type: "array", items: { type: "string" } },
      },
    },
    expected:
      "e83bf68c37bbac71b49d899470b4fef300c34f53c28bd4fbe4d7aad38a6fbc1f",
  },
  {
    label: "V7_numbers",
    name: "math.compute",
    description: "Numeric computation",
    parameters: {
      type: "object",
      properties: {
        x: { type: "integer", minimum: 0, maximum: 100 },
        y: { type: "number" },
        scale: { type: "number", default: 1.5 },
      },
    },
    expected:
      "aa3250631d691218a58ac2062241316391e6b26a803d4b81cd6e9242c607a721",
  },
];

describe("contractHash cross-language parity", () => {
  for (const v of PARITY_VECTORS) {
    it(`vector ${v.label} matches Rust + Python`, () => {
      const actual = contractHash({
        name: v.name,
        description: v.description,
        parameters: v.parameters,
      });
      expect(actual).toBe(v.expected);
    });
  }

  it("key-order independence — schemas with different insertion orders hash equal", () => {
    const p1 = {
      type: "object",
      properties: { a: { type: "string" }, b: { type: "integer" } },
    };
    const p2 = {
      properties: { b: { type: "integer" }, a: { type: "string" } },
      type: "object",
    };
    expect(
      contractHash({ name: "t", description: "d", parameters: p1 }),
    ).toBe(contractHash({ name: "t", description: "d", parameters: p2 }));
  });

  it("deterministic across calls", () => {
    const h1 = contractHash({ name: "Bash", description: "", parameters: {} });
    const h2 = contractHash({ name: "Bash", description: "", parameters: {} });
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(64);
  });
});
