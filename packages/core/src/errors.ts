/** An error the API returns to the caller as `{ error: code }` with this HTTP status. */
export class MusterError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message?: string,
    /** Sent as Retry-After on 429 responses. */
    readonly retryAfterSeconds?: number,
  ) {
    super(message ?? code);
    this.name = 'MusterError';
  }
}
