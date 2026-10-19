import { context, SpanStatusCode, trace, type Attributes, type Span } from '@opentelemetry/api';
import { MusterError } from './errors.js';

/**
 * Distributed tracing for the muster API (OB-60178).
 *
 * Muster core has no Langfuse path by design (20.4: no LLM path, no spans in the core), so these
 * spans are plain OpenTelemetry, not Langfuse observations: `@opentelemetry/api` only, which is a
 * no-op until a deployment registers a real tracer provider (e.g. an OTLP exporter). No LLM
 * semantics are attached; the spans trace the request path the way the structured request log
 * does. The Nexus side emits its own `nexus.muster.*` spans (`bridge.cycle`, `delivery.adapter`,
 * `delivery.reconciler`) through `runWithLangfuseTrace`; the names here extend the same
 * `nexus.muster.*` namespace so both sides correlate in one trace viewer.
 */

/** Span names live under `nexus.muster.*`; the template type rejects anything else at compile time. */
export type MusterSpanName = `nexus.muster.${string}`;

const tracer = trace.getTracer('nexus.muster');

/** Client errors (4xx) are recorded on the span but are not span failures. */
function isExpectedError(err: unknown): boolean {
  return err instanceof MusterError && err.status < 500;
}

/**
 * Runs `fn` inside an active `nexus.muster.*` span, mirroring the Nexus `runWithLangfuseTrace`
 * shape: a name plus attributes, exceptions recorded, the span always ended, the error rethrown.
 * `parentSpan` wires an explicit parent instead of relying on ambient async context propagation,
 * so the parent/child relationship holds under any tracer provider. With no provider registered
 * the API is a no-op and this costs essentially nothing on the hot path.
 *
 * Span-name cardinality is fixed: names are string literals at the call sites, never built from
 * request data. Attribute values stay low-cardinality too (types, counts, bounded error codes);
 * nothing client-sized (bodies, idempotency keys, recipient lists) is attached.
 */
export async function runWithSpan<T>(
  name: MusterSpanName,
  attributes: Attributes,
  fn: (span: Span) => Promise<T> | T,
  parentSpan?: Span,
): Promise<T> {
  const parentContext = parentSpan
    ? trace.setSpanContext(context.active(), parentSpan.spanContext())
    : context.active();
  return tracer.startActiveSpan(name, { attributes }, parentContext, async (span) => {
    try {
      return await fn(span);
    } catch (err) {
      span.recordException(err as Error);
      if (err instanceof MusterError) span.setAttribute('muster.error.code', err.code);
      if (!isExpectedError(err)) span.setStatus({ code: SpanStatusCode.ERROR });
      throw err;
    } finally {
      span.end();
    }
  });
}
