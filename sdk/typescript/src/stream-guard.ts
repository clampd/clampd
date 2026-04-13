/**
 * Stream interception for OpenAI and Anthropic streaming responses.
 *
 * Accumulates tool call chunks from streaming responses, guards them
 * through the Clampd proxy, and only releases chunks once approved.
 * Text/content chunks pass through immediately with zero added latency.
 */

import { ClampdClient, type ProxyResponse } from "./client.js";
import { ClampdBlockedError } from "./interceptor.js";
import { withDelegation, getDelegation, getCallerAgentId } from "./delegation.js";

// ── Types ────────────────────────────────────────────────────────

export interface StreamGuardOptions {
  agentId: string;
  targetUrl?: string;
  failOpen?: boolean;
  authorizedTools?: string[];
}

/** Minimal OpenAI streaming chunk shape. */
interface OpenAIChunk {
  choices?: Array<{
    index?: number;
    delta?: {
      content?: string | null;
      tool_calls?: Array<{
        index: number;
        id?: string;
        type?: string;
        function?: {
          name?: string;
          arguments?: string;
        };
      }>;
    };
    finish_reason?: string | null;
  }>;
  [key: string]: unknown;
}

/** Accumulated tool call state for OpenAI. */
interface PendingOpenAIToolCall {
  index: number;
  name: string;
  argumentFragments: string[];
}

/** Minimal Anthropic streaming event shape. */
interface AnthropicStreamEvent {
  type: string;
  index?: number;
  content_block?: {
    type: string;
    id?: string;
    name?: string;
    input?: Record<string, unknown>;
  };
  delta?: {
    type?: string;
    text?: string;
    partial_json?: string;
    stop_reason?: string;
  };
  [key: string]: unknown;
}

/** Accumulated tool call state for Anthropic. */
interface PendingAnthropicToolCall {
  blockIndex: number;
  name: string;
  jsonFragments: string[];
  bufferedEvents: AnthropicStreamEvent[];
}

// ── Proxy helper ─────────────────────────────────────────────────

async function guardToolCall(
  client: ClampdClient,
  toolName: string,
  toolArgs: Record<string, unknown>,
  opts: StreamGuardOptions,
): Promise<void> {
  await withDelegation(opts.agentId, async () => {
    const delegation = getDelegation();
    const proxyParams: Record<string, unknown> = { ...toolArgs };
    if (delegation && delegation.chain.length > 1) {
      proxyParams._delegation = {
        caller_agent_id: getCallerAgentId(),
        delegation_chain: delegation.chain,
        delegation_trace_id: delegation.traceId,
      };
    }

    try {
      const res = await client.proxy(
        toolName,
        proxyParams,
        opts.targetUrl ?? "",
        undefined,
        undefined,
        opts.authorizedTools,
      );
      if (!res.allowed) {
        // Respect failOpen for gateway errors
        if (opts.failOpen && res._gatewayError) {
          return;
        }
        throw new ClampdBlockedError(res);
      }
    } catch (e) {
      if (e instanceof ClampdBlockedError) throw e;
      if (!opts.failOpen) throw new ClampdBlockedError({
        request_id: "error",
        allowed: false,
        risk_score: 1.0,
        denial_reason: String(e),
        latency_ms: 0,
        degraded_stages: [],
        session_flags: [],
      });
    }
  });
}

// ── OpenAI stream guard ──────────────────────────────────────────

/**
 * Wraps an OpenAI streaming async iterable to intercept tool calls.
 * Text chunks pass through immediately. Tool call chunks are buffered
 * until complete, then guarded through the proxy before being released.
 *
 * Uses a SHARED buffer (not per-tool-call) for two reasons:
 *
 * 1. OpenAI sends a single chunk with deltas for multiple tool calls.
 *    Per-tool-call buffers would either lose chunks (only store in one)
 *    or duplicate them (store in all, yield the same chunk N times).
 *
 * 2. Parallel tool calls in the same LLM response are atomic — if the
 *    model says "call weather AND calendar", both must be approved before
 *    either executes. If one is denied, the entire response is blocked.
 *    Partial release of one tool call's chunks would give the consumer
 *    an incomplete response that can't be acted on.
 */
export function guardOpenAIStream(
  stream: AsyncIterable<unknown>,
  client: ClampdClient,
  opts: StreamGuardOptions,
): AsyncIterable<unknown> {
  const guardedIterator = async function* (): AsyncIterableIterator<unknown> {
    const pending = new Map<number, PendingOpenAIToolCall>();
    // Shared buffer: all tool call chunks held until ALL tool calls are guarded.
    const bufferedChunks: OpenAIChunk[] = [];
    let hasToolCalls = false;

    for await (const rawChunk of stream) {
      const chunk = rawChunk as OpenAIChunk;
      const choice = chunk.choices?.[0];

      if (!choice?.delta?.tool_calls?.length) {
        // No tool call data — yield text/other chunks immediately
        // But only if we haven't started accumulating tool calls,
        // or if this is a non-tool chunk interleaved
        if (!hasToolCalls) {
          yield chunk;
          continue;
        }
        // Buffer finish chunks until tool calls are guarded
        if (choice?.finish_reason) {
          // Guard all accumulated tool calls now
          for (const [, tc] of pending) {
            const argsStr = tc.argumentFragments.join("");
            let toolArgs: Record<string, unknown>;
            try {
              toolArgs = JSON.parse(argsStr);
            } catch {
              toolArgs = { raw: argsStr };
            }
            await guardToolCall(client, tc.name, toolArgs, opts);
          }

          // Release all buffered chunks
          for (const buffered of bufferedChunks) {
            yield buffered;
          }
          bufferedChunks.length = 0;
          pending.clear();
          hasToolCalls = false;

          // Now yield the finish chunk
          yield chunk;
          continue;
        }

        yield chunk;
        continue;
      }

      // Tool call deltas present — buffer them
      hasToolCalls = true;
      for (const tcDelta of choice.delta.tool_calls) {
        const idx = tcDelta.index;
        if (!pending.has(idx)) {
          pending.set(idx, {
            index: idx,
            name: tcDelta.function?.name ?? "unknown",
            argumentFragments: [],
          });
        }
        const tc = pending.get(idx)!;
        if (tcDelta.function?.name && !tc.name) {
          tc.name = tcDelta.function.name;
        }
        if (tcDelta.function?.arguments) {
          tc.argumentFragments.push(tcDelta.function.arguments);
        }
      }
      // Buffer the entire chunk (released after guard approval)
      bufferedChunks.push(chunk);
    }

    // Stream ended — guard any remaining tool calls
    if (pending.size > 0) {
      for (const [, tc] of pending) {
        const argsStr = tc.argumentFragments.join("");
        let toolArgs: Record<string, unknown>;
        try {
          toolArgs = JSON.parse(argsStr);
        } catch {
          toolArgs = { raw: argsStr };
        }
        await guardToolCall(client, tc.name, toolArgs, opts);
      }
      for (const buffered of bufferedChunks) {
        yield buffered;
      }
    }
  };

  // Return a Proxy that intercepts Symbol.asyncIterator but delegates
  // everything else (e.g. .controller, .toReadableStream()) to the original
  return new Proxy(stream as object, {
    get(target, prop, receiver) {
      if (prop === Symbol.asyncIterator) {
        return () => guardedIterator();
      }
      return Reflect.get(target, prop, receiver);
    },
  }) as AsyncIterable<unknown>;
}

// ── Anthropic stream guard ───────────────────────────────────────

/**
 * Wraps an Anthropic streaming async iterable to intercept tool_use blocks.
 * Text events pass through immediately. Tool use events are buffered per-block,
 * guarded at content_block_stop, then released.
 */
export function guardAnthropicStream(
  stream: AsyncIterable<unknown>,
  client: ClampdClient,
  opts: StreamGuardOptions,
): AsyncIterable<unknown> {
  const guardedIterator = async function* (): AsyncIterableIterator<unknown> {
    let currentToolCall: PendingAnthropicToolCall | null = null;

    for await (const rawEvent of stream) {
      const event = rawEvent as AnthropicStreamEvent;

      switch (event.type) {
        case "content_block_start": {
          if (event.content_block?.type === "tool_use") {
            // Start buffering a tool_use block
            currentToolCall = {
              blockIndex: event.index ?? 0,
              name: event.content_block.name ?? "unknown",
              jsonFragments: [],
              bufferedEvents: [event],
            };
          } else {
            // Text block start — pass through
            yield event;
          }
          break;
        }

        case "content_block_delta": {
          if (currentToolCall && event.delta?.type === "input_json_delta") {
            // Accumulate JSON fragments for the tool call
            if (event.delta.partial_json) {
              currentToolCall.jsonFragments.push(event.delta.partial_json);
            }
            currentToolCall.bufferedEvents.push(event);
          } else {
            // Text delta — pass through
            yield event;
          }
          break;
        }

        case "content_block_stop": {
          if (currentToolCall && event.index === currentToolCall.blockIndex) {
            // Tool block complete — guard it
            currentToolCall.bufferedEvents.push(event);
            const argsStr = currentToolCall.jsonFragments.join("");
            let toolArgs: Record<string, unknown>;
            try {
              toolArgs = argsStr ? JSON.parse(argsStr) : {};
            } catch {
              toolArgs = { raw: argsStr };
            }

            await guardToolCall(client, currentToolCall.name, toolArgs, opts);

            // Allowed — release buffered events
            for (const buffered of currentToolCall.bufferedEvents) {
              yield buffered;
            }
            currentToolCall = null;
          } else {
            // Text block stop — pass through
            yield event;
          }
          break;
        }

        default:
          // message_start, message_delta, message_stop, ping — pass through
          yield event;
          break;
      }
    }
  };

  return new Proxy(stream as object, {
    get(target, prop, receiver) {
      if (prop === Symbol.asyncIterator) {
        return () => guardedIterator();
      }
      return Reflect.get(target, prop, receiver);
    },
  }) as AsyncIterable<unknown>;
}
