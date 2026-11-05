/**
 * Payment and checkout mandate-chain processing - a faithful port of AP2's
 * `payment_mandate_chain.py` and `checkout_mandate_chain.py`. Operates on already-decoded,
 * already-verified payloads (parsed from an SD-JWT presentation elsewhere - see
 * `sd-jwt-presentation.ts`); this module owns only the business-constraint and hash-chain
 * linking logic, matching upstream's own separation between SD-JWT crypto and mandate semantics.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { createHash } from 'node:crypto';
import { checkCheckoutConstraints, checkPaymentConstraints } from './constraints.js';
import type { Checkout, CheckoutMandate, MandateContext, OpenCheckoutMandate, OpenPaymentMandate, PaymentMandate } from './types.js';

function base64UrlDecode(input: string): Buffer {
	return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/** base64url(SHA-256(utf8Bytes(jwtCompact))) - the hash both `checkout_hash` and `transaction_id` use. */
export function sha256Base64Url(jwtCompact: string): string {
	return createHash('sha256').update(jwtCompact, 'utf8').digest('base64url');
}

export class PaymentMandateChain {
	constructor(
		readonly openMandate: OpenPaymentMandate,
		readonly closedMandate: PaymentMandate,
	) {}

	static parse(payloads: readonly [OpenPaymentMandate, PaymentMandate]): PaymentMandateChain {
		return new PaymentMandateChain(payloads[0], payloads[1]);
	}

	/**
	 * Verify the chain's constraints. `expectedTransactionId` checks the closed mandate's
	 * `transaction_id`; `expectedOpenCheckoutHash` is forwarded to any `payment.reference`
	 * constraint. Returns violation messages, or an empty array if none.
	 */
	verify(options: { expectedTransactionId?: string; expectedOpenCheckoutHash?: string; mandateContext?: MandateContext } = {}): string[] {
		const violations = checkPaymentConstraints(this.openMandate, this.closedMandate, options.expectedOpenCheckoutHash, options.mandateContext);
		if (options.expectedTransactionId !== undefined && options.expectedTransactionId !== this.closedMandate.transaction_id) {
			violations.push(`Payment transaction_id mismatch: expected ${options.expectedTransactionId}, got ${this.closedMandate.transaction_id}`);
		}
		return violations;
	}
}

export class CheckoutMandateChain {
	constructor(
		readonly openMandate: OpenCheckoutMandate,
		readonly closedMandate: CheckoutMandate,
	) {}

	static parse(payloads: readonly [OpenCheckoutMandate, CheckoutMandate]): CheckoutMandateChain {
		return new CheckoutMandateChain(payloads[0], payloads[1]);
	}

	/**
	 * Verify the chain's constraints against the decoded `checkout_jwt` payload.
	 * `expectedCheckoutHash` checks the closed mandate's `checkout_hash`.
	 */
	verify(checkoutJwt: string, options: { expectedCheckoutHash?: string } = {}): string[] {
		let checkout: Checkout;
		try {
			checkout = extractParsedCheckoutObject(checkoutJwt);
		} catch (error) {
			return [error instanceof Error ? error.message : String(error)];
		}

		const violations = checkCheckoutConstraints(this.openMandate, checkout);
		if (options.expectedCheckoutHash !== undefined && options.expectedCheckoutHash !== this.closedMandate.checkout_hash) {
			violations.push(`Checkout checkout_hash mismatch: expected ${options.expectedCheckoutHash}, got ${this.closedMandate.checkout_hash}`);
		}
		return violations;
	}
}

/** Extracts the Checkout object from the checkout_jwt's payload segment. Does NOT verify the
 * JWT's signature - matching upstream, which treats that as the merchant-trust layer's job,
 * separate from mandate-chain constraint checking. */
function extractParsedCheckoutObject(checkoutJwt: string): Checkout {
	const parts = checkoutJwt.split('.');
	if (parts.length !== 3) throw new Error('Malformed checkout_jwt: expected header.payload.signature');
	let decoded: unknown;
	try {
		decoded = JSON.parse(base64UrlDecode(parts[1] as string).toString('utf8'));
	} catch (error) {
		throw new Error(`Invalid JSON in checkout_jwt payload: ${error instanceof Error ? error.message : String(error)}`);
	}
	if (typeof decoded !== 'object' || decoded === null) throw new Error('checkout_jwt payload failed schema validation: not an object');
	const record = decoded as Record<string, unknown>;
	if (typeof record.id !== 'string' || !Array.isArray(record.line_items) || typeof record.status !== 'string' || typeof record.currency !== 'string') {
		throw new Error('checkout_jwt payload failed schema validation: missing required Checkout fields');
	}
	return decoded as Checkout;
}
