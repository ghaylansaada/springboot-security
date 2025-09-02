package io.ghaylan.springboot.security.model.token

/**
 * Enumeration of valid token scopes in the security framework.
 *
 * These scopes represent the intent and usage constraints of token types used within the authentication system.
 * Each token enum implementing [TokenAccessPolicy] must declare its scope using one of the values below.
 *
 * ## Token Scope Constraints
 * - `ACCESS`: Can be used by **multiple** token types (e.g., for different clients or flows).
 * - `REFRESH`: **Exactly one** token type must be assigned this scope in a project.
 * - `INTERNAL`: **Exactly one** token type must be assigned this scope in a project.
 */
enum class TokenAccessScope
{
	/**
	 * Tokens used to authenticate access to secured user endpoints.
	 *
	 * Typically short-lived and bearer-style, these are issued upon user login and required for accessing protected APIs.
	 */
	ACCESS,

	/**
	 * Tokens used to renew access tokens without requiring re-authentication.
	 *
	 * These are long-lived and stored securely on the client side.
	 * Only one token type should be assigned this scope per project.
	 */
	REFRESH,

	/**
	 * Tokens used strictly for service-to-service or system-level internal communication.
	 *
	 * Reserved for authenticating internal operations and accessing `@InternalEndpoint`s.
	 * Only one token type should be assigned this scope per project.
	 */
	INTERNAL
}