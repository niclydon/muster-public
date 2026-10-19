const ALLOWED_PATHS = new Set([
  '/health',
  '/metrics',
  '/v1/register',
  '/v1/launch-grants',
  '/v1/presence',
  '/v1/registry',
  '/v1/messages',
  '/v1/conditions',
]);

function metricPath(path: string): string {
  if (ALLOWED_PATHS.has(path)) return path;
  if (path.startsWith('/v1/deliveries/') && path.endsWith('/ack')) return '/v1/deliveries/:id/ack';
  if (path.startsWith('/v1/conditions/') && path.endsWith('/clear')) return '/v1/conditions/:id/clear';
  return 'other';
}

function metricMethod(method: string): string {
  return /^(GET|POST|PUT|HEAD)$/.test(method) ? method : 'other';
}

function isWrite(method: string, path: string): boolean {
  return method !== 'GET' && path !== '/health' && path !== '/metrics';
}

/** Process-local Prometheus text. Write p99 is not a claimed operations SLI until a durable scrape exists (OA-04). */
export class RequestMetrics {
  private readonly counts = new Map<string, number>();
  private readonly writeDurationsMs: number[] = [];

  constructor(private readonly maxWriteSamples = 5_000) {}

  observe(method: string, path: string, status: number, durationMs: number): void {
    const key = `${metricMethod(method)}\t${metricPath(path)}\t${status}`;
    this.counts.set(key, (this.counts.get(key) ?? 0) + 1);
    if (isWrite(method, path) && Number.isFinite(durationMs) && durationMs >= 0) {
      this.writeDurationsMs.push(durationMs);
      if (this.writeDurationsMs.length > this.maxWriteSamples) this.writeDurationsMs.shift();
    }
  }

  writeP99Ms(): number | null {
    const n = this.writeDurationsMs.length;
    if (n === 0) return null;
    const sorted = [...this.writeDurationsMs].sort((a, b) => a - b);
    const idx = Math.min(n - 1, Math.max(0, Math.ceil(n * 0.99) - 1));
    return sorted[idx] ?? null;
  }

  render(opts: { killSwitchOn: boolean }): string {
    const lines = [
      '# HELP muster_http_requests_total Muster API requests.',
      '# TYPE muster_http_requests_total counter',
    ];
    for (const [key, count] of [...this.counts.entries()].sort()) {
      const [method, path, status] = key.split('\t');
      lines.push(`muster_http_requests_total{method="${method}",path="${path}",status="${status}"} ${count}`);
    }
    const p99 = this.writeP99Ms();
    lines.push('# HELP muster_http_write_p99_milliseconds Write-path p99 latency from this process.');
    lines.push('# TYPE muster_http_write_p99_milliseconds gauge');
    lines.push(`muster_http_write_p99_milliseconds ${p99 === null ? 'NaN' : p99}`);
    lines.push('# HELP muster_kill_switch 1 when the operator kill switch is on (API read-only, adapters off).');
    lines.push('# TYPE muster_kill_switch gauge');
    lines.push(`muster_kill_switch ${opts.killSwitchOn ? 1 : 0}`);
    lines.push('');
    return lines.join('\n');
  }
}
