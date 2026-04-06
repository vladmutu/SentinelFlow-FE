const LOG_PREFIX = "[SF_LOG]";

function shouldLogInfo(): boolean {
  if (process.env.NEXT_PUBLIC_ENABLE_LOGS === "true") {
    return true;
  }
  return process.env.NODE_ENV !== "production";
}

type LogMeta = Record<string, unknown> | undefined;

function formatMessage(scope: string, event: string): string {
  return `${LOG_PREFIX}[${scope}] ${event}`;
}

export function logInfo(scope: string, event: string, meta?: LogMeta): void {
  if (!shouldLogInfo()) {
    return;
  }

  if (meta) {
    console.info(formatMessage(scope, event), meta);
    return;
  }

  console.info(formatMessage(scope, event));
}

export function logWarn(scope: string, event: string, meta?: LogMeta): void {
  if (meta) {
    console.warn(formatMessage(scope, event), meta);
    return;
  }

  console.warn(formatMessage(scope, event));
}

export function logError(scope: string, event: string, meta?: LogMeta): void {
  const strictErrorLogging = process.env.NEXT_PUBLIC_STRICT_ERROR_LOGS === "true";
  const logFn = strictErrorLogging ? console.error : console.warn;

  if (meta) {
    logFn(formatMessage(scope, event), meta);
    return;
  }

  logFn(formatMessage(scope, event));
}
