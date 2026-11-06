/**
 * Shared seams for the gate (chosen design: verifying userBuilder + enforcing wrapper). Kept
 * separate from @kya-os/mcp's own types so this package can swap verifier internals later
 * without touching the gate/wrapper call sites.
 *
 * DRAFT — early exploration, not reviewed or stable. See the repository README.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import type { VerifyProofDeps } from '@kya-os/mcp/card';
import type { User } from '@a2a-js/sdk/server';

/** What a verified write request carries forward to the wrapper. */
export interface VerifiedCaller {
	did: string;
	covered: { method: string; params: unknown };
}

/** The user shape @a2a-js/sdk's Express userBuilder seam expects back. */
export interface GateUser extends User {
	isAuthenticated: boolean;
	userName: string;
	verified?: VerifiedCaller;
	rejection?: string;
}

export type GateVerifyDeps = Pick<
	VerifyProofDeps,
	'resolveKey' | 'resolveDidKeys' | 'expectedAudience' | 'consumeNonceIfFresh' | 'now' | 'skewSec'
>;
