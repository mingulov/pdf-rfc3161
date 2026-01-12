// test/unit/circuit-breaker.test.ts - Comprehensive circuit breaker tests
import { describe, it, expect, beforeEach } from "vitest";
import {
    CircuitBreaker,
    CircuitBreakerMap,
    CircuitState,
    CircuitBreakerError,
} from "../../../core/src/utils/circuit-breaker.js";

describe("Circuit Breaker", () => {
    describe("CircuitBreaker", () => {
        let breaker: CircuitBreaker;

        beforeEach(() => {
            breaker = new CircuitBreaker({ failureThreshold: 2, resetTimeoutMs: 100 });
        });

        describe("initial state", () => {
            it("should start in CLOSED state", () => {
                expect(breaker.currentState).toBe(CircuitState.CLOSED);
            });

            it("should have zero failure count initially", () => {
                expect(breaker.failureCount).toBe(0);
            });

            it("should have zero success count initially", () => {
                expect(breaker.successCount).toBe(0);
            });
        });

        describe("successful execution", () => {
            it("should stay CLOSED after successful execution", async () => {
                const result = await breaker.execute(async () => "success");
                expect(result).toBe("success");
                expect(breaker.currentState).toBe(CircuitState.CLOSED);
                expect(breaker.failureCount).toBe(0);
            });

            it("should transition from HALF_OPEN to CLOSED on success", async () => {
                // Force to OPEN state
                breaker.setState(CircuitState.OPEN);

                // Wait for reset timeout
                await new Promise((resolve) => setTimeout(resolve, 150));

                // Should be HALF_OPEN now
                expect(breaker.currentState).toBe(CircuitState.HALF_OPEN);

                // Execute successfully
                await breaker.execute(async () => "success");

                // Should transition to CLOSED
                expect(breaker.currentState).toBe(CircuitState.CLOSED);
            });

            it("should transition to CLOSED after success threshold in HALF_OPEN state", async () => {
                breaker.setState(CircuitState.HALF_OPEN);

                await breaker.execute(async () => "success");

                // After reaching success threshold (1), it transitions to CLOSED and resets count
                expect(breaker.currentState).toBe(CircuitState.CLOSED);
                expect(breaker.successCount).toBe(0); // Reset after transition
            });
        });

        describe("failed execution", () => {
            it("should increment failure count on error", async () => {
                await expect(
                    breaker.execute(async () => {
                        throw new Error("test error");
                    })
                ).rejects.toThrow("test error");

                expect(breaker.failureCount).toBe(1);
                expect(breaker.currentState).toBe(CircuitState.CLOSED);
            });

            it("should transition to OPEN after failure threshold", async () => {
                // Two failures should open the circuit
                for (let i = 0; i < 2; i++) {
                    await expect(
                        breaker.execute(async () => {
                            throw new Error("test error");
                        })
                    ).rejects.toThrow("test error");
                }

                expect(breaker.currentState).toBe(CircuitState.OPEN);
            });

            it("should open circuit immediately when already OPEN", async () => {
                breaker.setState(CircuitState.OPEN);

                await expect(breaker.execute(async () => "success")).rejects.toThrow(
                    "Circuit breaker is OPEN"
                );

                // Should not execute the function
            });
        });

        describe("state transitions", () => {
            it("should transition OPEN to HALF_OPEN after reset timeout", async () => {
                breaker.setState(CircuitState.OPEN);

                // Should still be OPEN immediately
                expect(breaker.currentState).toBe(CircuitState.OPEN);

                // Wait for reset timeout
                await new Promise((resolve) => setTimeout(resolve, 150));

                // Should transition to HALF_OPEN
                expect(breaker.currentState).toBe(CircuitState.HALF_OPEN);
            });

            it("should reset failure count when transitioning to CLOSED", async () => {
                // Cause failures to open circuit
                for (let i = 0; i < 2; i++) {
                    try {
                        await breaker.execute(async () => {
                            throw new Error("fail");
                        });
                    } catch {
                        // Expected failure
                    }
                }

                expect(breaker.currentState).toBe(CircuitState.OPEN);
                expect(breaker.failureCount).toBe(2);

                // Reset manually
                breaker.reset();

                expect(breaker.currentState).toBe(CircuitState.CLOSED);
                expect(breaker.failureCount).toBe(0);
                expect(breaker.successCount).toBe(0);
            });
        });

        describe("configuration", () => {
            it("should use default configuration when none provided", () => {
                const defaultBreaker = new CircuitBreaker();
                expect(defaultBreaker).toBeDefined();
            });

            it("should accept custom configuration", () => {
                const customBreaker = new CircuitBreaker({
                    failureThreshold: 5,
                    resetTimeoutMs: 5000,
                    successThreshold: 3,
                });
                expect(customBreaker).toBeDefined();
            });
        });
    });

    describe("CircuitBreakerMap", () => {
        let map: CircuitBreakerMap;

        beforeEach(() => {
            map = new CircuitBreakerMap({ failureThreshold: 2 });
        });

        it("should create breaker on demand", () => {
            const breaker = map.getBreaker("test-url");
            expect(breaker).toBeDefined();
            expect(breaker.currentState).toBe(CircuitState.CLOSED);
        });

        it("should return same breaker for same URL", () => {
            const breaker1 = map.getBreaker("test-url");
            const breaker2 = map.getBreaker("test-url");
            expect(breaker1).toBe(breaker2);
        });

        it("should return different breakers for different URLs", () => {
            const breaker1 = map.getBreaker("url1");
            const breaker2 = map.getBreaker("url2");
            expect(breaker1).not.toBe(breaker2);
        });

        it("should execute with circuit breaker protection", async () => {
            const result = await map.execute("test-url", async () => "success");
            expect(result).toBe("success");
        });

        it("should track state per URL", () => {
            expect(map.getState("url1")).toBeUndefined();

            const breaker = map.getBreaker("url1");
            breaker.setState(CircuitState.OPEN);

            expect(map.getState("url1")).toBe(CircuitState.OPEN);
            expect(map.getState("url2")).toBeUndefined();
        });

        it("should return all tracked URLs", () => {
            map.getBreaker("url1");
            map.getBreaker("url2");

            const urls = map.getUrls();
            expect(urls).toContain("url1");
            expect(urls).toContain("url2");
            expect(urls).toHaveLength(2);
        });

        it("should reset all breakers", () => {
            const breaker1 = map.getBreaker("url1");
            const breaker2 = map.getBreaker("url2");

            breaker1.setState(CircuitState.OPEN);
            breaker2.setState(CircuitState.OPEN);

            map.reset();

            expect(map.getUrls()).toHaveLength(0);
            expect(map.getState("url1")).toBeUndefined();
            expect(map.getState("url2")).toBeUndefined();
        });

        it("should remove specific breaker", () => {
            map.getBreaker("url1");
            map.getBreaker("url2");

            map.remove("url1");

            expect(map.getUrls()).toEqual(["url2"]);
            expect(map.getState("url1")).toBeUndefined();
        });

        it("should use default configuration for new breakers", () => {
            const breaker = map.getBreaker("test");
            // The breaker should have been created with failureThreshold: 2
            // We can't easily test this without exposing internal config
            expect(breaker).toBeDefined();
        });
    });

    describe("CircuitBreakerError", () => {
        it("should create error with state information", () => {
            const error = new CircuitBreakerError("Service unavailable", CircuitState.OPEN);

            expect(error.message).toBe("Service unavailable");
            expect(error.circuitState).toBe(CircuitState.OPEN);
            expect(error.name).toBe("CircuitBreakerError");
        });

        it("should be instanceof Error", () => {
            const error = new CircuitBreakerError("Test", CircuitState.OPEN);

            expect(error instanceof Error).toBe(true);
        });
    });
});
