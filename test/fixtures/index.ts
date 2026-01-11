/**
 * Test Fixtures Index
 *
 * This module exports all test fixtures for TSA testing.
 *
 * @example
 * ```typescript
 * import { TSA_FIXTURES, getFixturesByTrustStatus } from './fixtures';
 *
 * // Get all qualified TSA responses
 * const qualified = getFixturesByTrustStatus('QUALIFIED');
 *
 * // Use a specific fixture
 * const digicert = TSA_FIXTURES.DIGICERT_GRANTED;
 * ```
 */

export * from "./tsa-responses.js";
