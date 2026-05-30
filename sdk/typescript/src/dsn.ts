/**
 * Clampd DSN parsing. A DSN supplies gatewayUrl + apiKey from one string.
 *
 * Format:
 *   clampd://<org_key>@<host>[:<port>]      // TLS
 *   clampd+http://<org_key>@<host>:<port>   // plaintext (local dev)
 *
 * <org_key> is the org API key (ag_live_… / ag_test_…). When the host is
 * omitted, the managed cloud gateway is used.
 *
 * Keep these semantics identical to the Python SDK (clampd/dsn.py).
 */

export const DEFAULT_GATEWAY_URL = "https://gateway.clampd.dev";

export interface Dsn {
  gatewayUrl: string;
  apiKey: string;
}

const TLS_SCHEMES = new Set(["clampd", "clampd+https", "https"]);
const PLAINTEXT_SCHEMES = new Set(["clampd+http", "http"]);

/**
 * Parse a Clampd DSN into `gatewayUrl` + `apiKey`.
 * @throws Error if the scheme is unrecognized or the org key is missing.
 */
export function parseDsn(dsn: string): Dsn {
  const raw = (dsn || "").trim();
  if (!raw) {
    throw new Error("Empty CLAMPD_DSN. Expected clampd://<org_key>@<host>");
  }

  // scheme://[user@]host[:port]
  const m = raw.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^@/]*)@([^/?#]*)/);
  if (!m) {
    throw new Error(
      "Invalid CLAMPD_DSN. Expected clampd://<org_key>@<host>",
    );
  }
  const [, scheme, orgKey, authority] = m;
  const schemeLc = scheme.toLowerCase();

  let proto: string;
  if (TLS_SCHEMES.has(schemeLc)) {
    proto = "https";
  } else if (PLAINTEXT_SCHEMES.has(schemeLc)) {
    proto = "http";
  } else {
    throw new Error(
      `Invalid CLAMPD_DSN scheme '${scheme}'. ` +
        "Expected clampd://<org_key>@<host> (or clampd+http:// for local dev).",
    );
  }

  if (!orgKey) {
    throw new Error(
      "CLAMPD_DSN is missing the org key. Expected clampd://<org_key>@<host>.",
    );
  }

  let gatewayUrl: string;
  if (authority) {
    // authority is host[:port]
    gatewayUrl = `${proto}://${authority}`;
  } else {
    gatewayUrl = DEFAULT_GATEWAY_URL;
  }

  return { gatewayUrl, apiKey: orgKey };
}
