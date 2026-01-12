/**
 * Logger interface for the library.
 * Allows consumers to customize how the library logs warnings and errors.
 */
export interface Logger {
    debug(message: string, ...args: unknown[]): void;
    info(message: string, ...args: unknown[]): void;
    warn(message: string, ...args: unknown[]): void;
    error(message: string, ...args: unknown[]): void;
}

/**
 * Default logger that prints to console for Warn and Error levels.
 * Debug and Info are silent by default to keep output clean.
 */
class ConsoleLogger implements Logger {
    debug(_message: string, ..._args: unknown[]): void {
        // No-op by default
    }

    info(_message: string, ..._args: unknown[]): void {
        // No-op by default
    }

    warn(message: string, ...args: unknown[]): void {
        console.warn(`[pdf-rfc3161] WARN: ${message}`, ...args);
    }

    error(message: string, ...args: unknown[]): void {
        console.error(`[pdf-rfc3161] ERROR: ${message}`, ...args);
    }
}

// Singleton instance
let currentLogger: Logger = new ConsoleLogger();

/**
 * Get the current logger instance.
 */
export function getLogger(): Logger {
    return currentLogger;
}

/**
 * Set a custom logger implementation.
 * @param logger The new logger to use
 */
export function setLogger(logger: Logger): void {
    currentLogger = logger;
}

/**
 * Silence all logging.
 */
export function disableLogging(): void {
    currentLogger = {
        debug: () => {
            /* no-op */
        },
        info: () => {
            /* no-op */
        },
        warn: () => {
            /* no-op */
        },
        error: () => {
            /* no-op */
        },
    };
}
