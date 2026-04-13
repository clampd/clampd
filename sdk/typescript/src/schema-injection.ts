/**
 * Schema injection / tool poisoning detection for the Clampd TypeScript SDK.
 *
 * Scans conversation messages for attempts to inject or redefine tool schemas,
 * steer agents toward different tools via DEPRECATED tags, or weaken schema
 * constraints.
 */

// ── Types ─────────────────────────────────────────────────

export interface SchemaInjectionWarning {
  alertType: string;     // "xml_injection" | "json_injection" | "tool_steering" | "constraint_weakening"
  matchedPattern: string;
  riskScore: number;
  messageIndex: number;
}

// ── Compiled patterns ─────────────────────────────────────

interface PatternGroup {
  alertType: string;
  riskScore: number;
  patterns: RegExp[];
}

const PATTERN_GROUPS: PatternGroup[] = [
  {
    alertType: "xml_injection",
    riskScore: 0.95,
    patterns: [
      /<\/?functions\s*>/i,
      /<function[\s>]/i,
      /<\/?tool\s*>/i,
      /<\/?tool_call\s*>/i,
      /<\/?tool_code\s*>/i,
      /<\/?tools\s*>/i,
      /<system\s*>/i,
    ],
  },
  {
    alertType: "json_injection",
    riskScore: 0.90,
    patterns: [
      /"inputSchema"\s*:/,
      /"parameters"\s*:\s*\{[^}]*"type"\s*:\s*"object"/,
    ],
  },
  {
    alertType: "constraint_weakening",
    riskScore: 0.88,
    patterns: [
      /allowed_directories["\s]*:\s*\[\s*\]/i,
      /allowed_directories["\s]*:\s*\["\*"\]/i,
      /"type"\s*:\s*"any"/,
      /"required"\s*:\s*\[\s*\]/,
    ],
  },
  {
    alertType: "tool_steering",
    riskScore: 0.80,
    patterns: [
      // Multi-word patterns only — single words like "DEPRECATED" cause
      // false positives in normal conversation (alert fatigue risk).
      /use\s+\w+\s+instead\b/i,
      /\breplaced\s+by\b/i,
      /\bsuperseded\s+by\b/i,
    ],
  },
];

// ── Scanner ───────────────────────────────────────────────

interface MessageLike {
  role?: string;
  content?: string | unknown;
  [key: string]: unknown;
}

/**
 * Scan conversation messages for schema injection / tool poisoning attempts.
 *
 * Checks all message content (user, system, assistant turns) for:
 * - XML tool definition tags (<functions>, <tool>, etc.)
 * - JSON tool definition structures ("inputSchema", "parameters")
 * - Tool confusion via DEPRECATED/OBSOLETE steering
 * - Schema constraint weakening (allowed_directories: [], type: "any")
 *
 * @returns Warnings sorted by risk (highest first). Empty array = clean.
 */
export function scanForSchemaInjection(messages: MessageLike[]): SchemaInjectionWarning[] {
  const warnings: SchemaInjectionWarning[] = [];

  for (let idx = 0; idx < messages.length; idx++) {
    const msg = messages[idx];
    let content = "";
    if (typeof msg.content === "string") {
      content = msg.content;
    } else if (Array.isArray(msg.content)) {
      // Anthropic-style content blocks: [{type: "text", text: "..."}]
      content = (msg.content as Array<Record<string, unknown>>)
        .filter((b) => b.type === "text" && typeof b.text === "string")
        .map((b) => b.text as string)
        .join("\n");
    }
    if (!content) continue;

    for (const group of PATTERN_GROUPS) {
      for (const pattern of group.patterns) {
        const match = pattern.exec(content);
        if (match) {
          warnings.push({
            alertType: group.alertType,
            matchedPattern: match[0],
            riskScore: group.riskScore,
            messageIndex: idx,
          });
          break; // One match per group per message
        }
      }
    }
  }

  // Sort by risk (highest first)
  warnings.sort((a, b) => b.riskScore - a.riskScore);
  return warnings;
}
