import { describe, expect, it } from 'vitest';
import {
	JwksUriValidationError,
	type JwksUriValidationErrorReason,
	validateJwksUri,
	type ValidateJwksUriOptions,
} from './jwks-uri.js';

const validClientId = 'https://client.example.com/oauth/client.json';
const options = { allowedDomains: [], maxLength: 255 };

// Assert on `reason` directly so the test still detects regressions if the error's `message` ever decouples from
// `reason`. `toThrow(new JwksUriValidationError('x'))` only matches the message string.
function expectRejection(
	value: unknown,
	clientId: string,
	opts: ValidateJwksUriOptions,
	reason: JwksUriValidationErrorReason,
) {
	let caught: unknown;

	try {
		validateJwksUri(value, clientId, opts);
	} catch (err) {
		caught = err;
	}

	expect(caught).toBeInstanceOf(JwksUriValidationError);
	expect(caught).toMatchObject({ reason });
}

describe('validateJwksUri', () => {
	it('returns the input unchanged for a valid same-origin HTTPS URL', () => {
		const value = 'https://client.example.com/.well-known/jwks.json';
		expect(validateJwksUri(value, validClientId, options)).toBe(value);
	});

	it.each([
		{ label: 'undefined', value: undefined },
		{ label: 'null', value: null },
		{ label: 'number', value: 42 },
		{ label: 'empty string', value: '' },
	])('rejects $label with reason "required"', ({ value }) => {
		expectRejection(value, validClientId, options, 'required');
	});

	it('rejects a value longer than maxLength with reason "too_long"', () => {
		const value = `https://client.example.com/${'a'.repeat(250)}`;
		expectRejection(value, validClientId, options, 'too_long');
	});

	it.each([
		{ label: 'unparseable jwks_uri', value: 'not a url', clientId: validClientId },
		{ label: 'unparseable clientId', value: 'https://client.example.com/jwks', clientId: 'not-a-url' },
	])('rejects $label with reason "invalid_url"', ({ value, clientId }) => {
		expectRejection(value, clientId, options, 'invalid_url');
	});

	it.each(['http://client.example.com/jwks.json', 'ftp://client.example.com/jwks.json', 'data:application/json,{}'])(
		'rejects non-https scheme %s with reason "invalid_scheme"',
		(value) => {
			expectRejection(value, validClientId, options, 'invalid_scheme');
		},
	);

	it.each([
		'https://user@client.example.com/jwks.json',
		'https://user:pass@client.example.com/jwks.json',
		'https://:pass@client.example.com/jwks.json',
	])('rejects URL with credentials %s with reason "credentials"', (value) => {
		expectRejection(value, validClientId, options, 'credentials');
	});

	it.each(['https://client.example.com/jwks.json#section', 'https://client.example.com/jwks.json#'])(
		'rejects URL with fragment %s with reason "fragment"',
		(value) => {
			expectRejection(value, validClientId, options, 'fragment');
		},
	);

	it.each([
		{ label: 'parent traversal segment', value: 'https://client.example.com/oauth/../jwks.json' },
		{ label: 'current directory segment', value: 'https://client.example.com/oauth/./jwks.json' },
		{ label: 'trailing parent segment', value: 'https://client.example.com/oauth/..' },
		{ label: 'trailing current segment', value: 'https://client.example.com/oauth/.' },
	])('rejects raw text path with $label with reason "dot_segments"', ({ value }) => {
		expectRejection(value, validClientId, options, 'dot_segments');
	});

	it.each([
		{ label: 'IPv4 literal', value: 'https://192.168.1.1/jwks.json' },
		{ label: 'IPv6 literal', value: 'https://[::1]/jwks.json' },
		{ label: 'public IPv4 literal', value: 'https://8.8.8.8/jwks.json' },
	])('rejects $label with reason "ip_literal"', ({ value }) => {
		expectRejection(value, validClientId, options, 'ip_literal');
	});

	it.each([
		{ label: 'different host', value: 'https://other.example.com/jwks.json' },
		{ label: 'different port', value: 'https://client.example.com:8443/jwks.json' },
		{ label: 'different subdomain', value: 'https://sub.client.example.com/jwks.json' },
	])('rejects $label with reason "cross_origin"', ({ value }) => {
		expectRejection(value, validClientId, options, 'cross_origin');
	});

	it.each([
		{ label: 'default port :443 stripped', value: 'https://client.example.com:443/jwks.json' },
		{ label: 'trailing slash added when path missing', value: 'https://client.example.com' },
		{ label: 'percent-encoded space decoded', value: 'https://client.example.com/jwks file.json' },
		{ label: 'uppercase hostname lowercased', value: 'https://CLIENT.EXAMPLE.COM/jwks.json' },
	])('rejects $label with reason "non_canonical"', ({ value }) => {
		expectRejection(value, validClientId, options, 'non_canonical');
	});

	describe('disallowed_domain', () => {
		it('rejects hostname not in allowedDomains list', () => {
			const value = 'https://other.example.com/jwks.json';
			const clientId = 'https://other.example.com/oauth/client.json';

			expectRejection(
				value,
				clientId,
				{ allowedDomains: ['allowed.example.com'], maxLength: 255 },
				'disallowed_domain',
			);
		});

		it('accepts hostname that matches an allowed exact domain', () => {
			const value = 'https://client.example.com/jwks.json';

			expect(validateJwksUri(value, validClientId, { allowedDomains: ['client.example.com'], maxLength: 255 })).toBe(
				value,
			);
		});

		it('accepts hostname that matches an allowed wildcard pattern', () => {
			const value = 'https://client.example.com/jwks.json';
			expect(validateJwksUri(value, validClientId, { allowedDomains: ['*.example.com'], maxLength: 255 })).toBe(value);
		});

		it('skips the allowlist check when allowedDomains is empty', () => {
			const value = 'https://client.example.com/jwks.json';
			expect(validateJwksUri(value, validClientId, { allowedDomains: [], maxLength: 255 })).toBe(value);
		});
	});

	describe('JwksUriValidationError', () => {
		it('exposes the reason as both the error name and reason property', () => {
			const error = new JwksUriValidationError('required');
			expect(error).toBeInstanceOf(Error);
			expect(error.name).toBe('JwksUriValidationError');
			expect(error.reason).toBe('required');
			expect(error.message).toBe('required');
		});
	});
});
