/**
 * A millisecond clock used for elapsed-deadline enforcement. Any injected
 * clock must be monotonic: wall-clock steps (NTP, DST, manual changes)
 * must never move it backward, or an elapsed deadline could read as
 * unexpired and overdue work could be accepted as success.
 */
export type MonotonicClock = () => number;

/**
 * Shared monotonic now() in milliseconds. `performance.now()` is monotonic
 * on every supported runtime (Node, browsers, workers, edge); `Date.now()`
 * is only a fallback for exotic hosts without `performance`.
 */
export function monotonicNow(): number {
    if (typeof performance !== "undefined" && typeof performance.now === "function") {
        return performance.now();
    }
    return Date.now();
}
