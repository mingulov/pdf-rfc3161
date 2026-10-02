// Millisecond read of a caller date; hostile shapes yield NaN, never throw.
// Reads the intrinsic slot, never the overridable method: a subclass or
// own getTime must not substitute the validation instant (T09b-F1).
export function snapshotDateMs(value: unknown): number {
    try {
        return value instanceof Date ? Date.prototype.getTime.call(value) : NaN;
    } catch {
        return NaN;
    }
}
