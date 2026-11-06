/**
 * Adapts `verifyLedgerAnchoredStatus` to `@kya-os/mcp`'s `StatusListResolver` seam
 * (`checkStatus(status): Promise<boolean>`), so delegation chain verification can use the
 * ledger-anchored check in place of a signed-proof-based one. One resolver instance per trusted
 * issuer DID - the same shape `@kya-os/mcp/cheqd`'s own `createCheqdStatusListResolver` uses, so
 * swapping between the two needs no call-site change.
 *
 * Fails closed per the seam's contract: THROWS (never returns a value) on anything unprovable,
 * so `DelegationCredentialVerifier` denies rather than treating an unresolvable status as "not
 * revoked".
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import {
	verifyLedgerAnchoredStatus,
	type LedgerAnchoredStatusOptions,
	type StatusEntry,
} from './ledger-anchored.js';

/** The subset of `@kya-os/mcp`'s `CredentialStatus` this resolver reads. */
export interface MinimalCredentialStatus {
	readonly statusListIndex: string;
	readonly statusListCredential: string;
	readonly statusPurpose: 'revocation' | 'suspension';
	readonly statusSize?: number;
	readonly [key: string]: unknown;
}

export interface LedgerAnchoredStatusListResolverOptions extends LedgerAnchoredStatusOptions {
	/** Only status entries issued by this DID are trusted. */
	readonly expectedIssuerDid: string;
}

export interface StatusListResolverLike {
	checkStatus(status: MinimalCredentialStatus): Promise<boolean>;
}

export function createLedgerAnchoredStatusListResolver(
	options: LedgerAnchoredStatusListResolverOptions,
): StatusListResolverLike {
	return {
		async checkStatus(status: MinimalCredentialStatus): Promise<boolean> {
			const entry: StatusEntry = {
				statusListCredential: status.statusListCredential,
				statusListIndex: status.statusListIndex,
				statusPurpose: status.statusPurpose,
				...(status.statusSize !== undefined ? { statusSize: status.statusSize } : {}),
			};
			const result = await verifyLedgerAnchoredStatus(entry, options.expectedIssuerDid, options);
			if (!result.ok) throw new Error(`ledger_anchored_status_unresolvable: ${result.reasons.join(',')}`);
			return result.revoked;
		},
	};
}
