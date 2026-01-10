/**
 * Circuit Breaker States
 */
export enum CircuitState {
    CLOSED = "CLOSED",
    OPEN = "OPEN",
    HALF_OPEN = "HALF_OPEN",
}

/**
 * Circuit Breaker configuration
 */
export interface CircuitBreakerConfig {
    /** Number of failures before opening the circuit (default: 5) */
    failureThreshold?: number;
    /** Time in ms before attempting half-open state (default: 30000) */
    resetTimeoutMs?: number;
    /** Success count needed to close from half-open (default: 1) */
    successThreshold?: number;
}

/**
 * Circuit Breaker for preventing cascade failures in distributed systems.
 *
 * State Machine:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: After failure threshold reached, requests fail immediately
 * - HALF_OPEN: After reset timeout, allows limited requests to test recovery
 *
 * Usage:
 * ```typescript
 * const breaker = new CircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 30000 });
 *
 * try {
 *     return await breaker.execute(() => fetchOCSP(url, request));
 * } catch (error) {
 *     if (breaker.currentState === CircuitState.OPEN) {
 *         console.log('Service is down, circuit is open');
 *     }
 * }
 * ```
 */
export class CircuitBreaker {
    private _state: CircuitState = CircuitState.CLOSED;
    private _failureCount = 0;
    private _successCount = 0;
    private _lastFailureTime = 0;
    private readonly config: Required<CircuitBreakerConfig>;

    constructor(config: CircuitBreakerConfig = {}) {
        this.config = {
            failureThreshold: config.failureThreshold ?? 5,
            resetTimeoutMs: config.resetTimeoutMs ?? 30000,
            successThreshold: config.successThreshold ?? 1,
        };
    }

    /**
     * Current state of the circuit breaker
     */
    get currentState(): CircuitState {
        // Check if we should transition from OPEN to HALF_OPEN
        if (this._state === CircuitState.OPEN) {
            if (Date.now() - this._lastFailureTime >= this.config.resetTimeoutMs) {
                this._state = CircuitState.HALF_OPEN;
                this._successCount = 0;
            }
        }
        return this._state;
    }

    /**
     * Get current failure count
     */
    get failureCount(): number {
        return this._failureCount;
    }

    /**
     * Get current success count (in half-open state)
     */
    get successCount(): number {
        return this._successCount;
    }

    /**
     * Execute a function with circuit breaker protection
     *
     * @param fn - The async function to execute
     * @returns The result of the function
     * @throws CircuitBreakerError if circuit is open
     */
    async execute<T>(fn: () => Promise<T>): Promise<T> {
        // Check state before execution
        if (this.currentState === CircuitState.OPEN) {
            throw new CircuitBreakerError(
                `Circuit breaker is OPEN. Service unavailable. Retry after ${String(this.config.resetTimeoutMs)}ms.`,
                this.currentState
            );
        }

        try {
            const result = await fn();
            this.onSuccess();
            return result;
        } catch (error) {
            this.onFailure();
            throw error;
        }
    }

    /**
     * Force the circuit breaker into a specific state (for testing/admin)
     */
    setState(state: CircuitState): void {
        this._state = state;
        if (state === CircuitState.CLOSED) {
            this._failureCount = 0;
            this._successCount = 0;
        } else if (state === CircuitState.OPEN) {
            this._lastFailureTime = Date.now();
        }
    }

    /**
     * Reset the circuit breaker to initial state
     */
    reset(): void {
        this._state = CircuitState.CLOSED;
        this._failureCount = 0;
        this._successCount = 0;
        this._lastFailureTime = 0;
    }

    private onSuccess(): void {
        if (this._state === CircuitState.HALF_OPEN) {
            this._successCount++;
            if (this._successCount >= this.config.successThreshold) {
                this._state = CircuitState.CLOSED;
                this._failureCount = 0;
                this._successCount = 0;
            }
        } else {
            // In CLOSED state, reset failure count on success
            this._failureCount = 0;
        }
    }

    private onFailure(): void {
        this._failureCount++;
        this._lastFailureTime = Date.now();

        if (this._state === CircuitState.HALF_OPEN) {
            // Any failure in HALF_OPEN goes back to OPEN
            this._state = CircuitState.OPEN;
        } else if (this._failureCount >= this.config.failureThreshold) {
            this._state = CircuitState.OPEN;
        }
    }
}

/**
 * Error thrown when circuit breaker is open
 */
export class CircuitBreakerError extends Error {
    constructor(
        message: string,
        public readonly circuitState: CircuitState
    ) {
        super(message);
        this.name = "CircuitBreakerError";
    }
}

/**
 * A map of circuit breakers keyed by service URL.
 * Useful for managing multiple independent services.
 */
export class CircuitBreakerMap {
    private readonly breakers = new Map<string, CircuitBreaker>();
    private readonly defaultConfig: CircuitBreakerConfig;

    constructor(defaultConfig: CircuitBreakerConfig = {}) {
        this.defaultConfig = defaultConfig;
    }

    /**
     * Get or create a circuit breaker for a specific URL
     */
    getBreaker(url: string): CircuitBreaker {
        if (!this.breakers.has(url)) {
            this.breakers.set(url, new CircuitBreaker(this.defaultConfig));
        }
        const breaker = this.breakers.get(url);
        if (!breaker) {
            throw new Error(`Circuit breaker not found for ${url}`);
        }
        return breaker;
    }

    /**
     * Execute with circuit breaker protection for a specific URL
     */
    async execute<T>(url: string, fn: () => Promise<T>): Promise<T> {
        const breaker = this.getBreaker(url);
        return breaker.execute(fn);
    }

    /**
     * Get all tracked URLs
     */
    getUrls(): string[] {
        return Array.from(this.breakers.keys());
    }

    /**
     * Get the state of a breaker for a specific URL
     */
    getState(url: string): CircuitState | undefined {
        return this.breakers.get(url)?.currentState;
    }

    /**
     * Clear all circuit breakers
     */
    reset(): void {
        for (const breaker of Array.from(this.breakers.values())) {
            breaker.reset();
        }
        this.breakers.clear();
    }

    /**
     * Remove a specific URL's circuit breaker
     */
    remove(url: string): void {
        this.breakers.delete(url);
    }
}
