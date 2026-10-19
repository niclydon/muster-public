const LEVELS = { minimal: 0, normal: 1, verbose: 2, debug: 3 } as const;

export type Logger = ReturnType<typeof createLogger>;

/** Tiered logger per the workspace LOGGING standard. Never pass tokens, signatures, or private keys. */
export function createLogger(component: string, level: string = process.env.LOG_LEVEL ?? 'normal') {
  const n: number = LEVELS[level as keyof typeof LEVELS] ?? LEVELS.normal;
  const prefix = `[${component}]`;
  return {
    logMinimal: (...args: unknown[]) => console.error(prefix, ...args),
    log: (...args: unknown[]) => {
      if (n >= LEVELS.normal) console.log(prefix, ...args);
    },
    logVerbose: (...args: unknown[]) => {
      if (n >= LEVELS.verbose) console.log(prefix, ...args);
    },
    logDebug: (...args: unknown[]) => {
      if (n >= LEVELS.debug) console.log(prefix, ...args);
    },
  };
}
