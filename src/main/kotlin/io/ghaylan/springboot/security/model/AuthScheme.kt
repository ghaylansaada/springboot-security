package io.ghaylan.springboot.security.model

/**
 * Defines the supported authentication schemes available for securing endpoints.
 *
 * This enum enumerates the authentication methods recognized by the security framework.
 * Each scheme represents a distinct authentication mechanism and informs how endpoints
 * enforce security policies.
 *
 * @param scheme The string identifier used in the `Authorization` HTTP header to specify the scheme.
 */
enum class AuthScheme(val scheme: String)
{
    /**
     * Bearer token authentication utilizing JWT (JSON Web Tokens).
     *
     * Expected header format:
     * ```
     * Authorization: Bearer <jwt_token>
     * ```
     *
     * Typically used for authenticating users with stateless tokens.
     */
    BEARER(scheme = "Bearer"),

    /**
     * API key authentication using secret keys.
     *
     * Expected header format:
     * ```
     * Authorization: ApiKey <api_key>
     * ```
     *
     * Commonly used by many APIs to authenticate users by providing a secret API key.
     * It is a widely adopted, straightforward method to grant access without complex token management.
     */
    API_KEY(scheme = "ApiKey"),

    /**
     * HMAC (Hash-based Message Authentication Code) signature authentication.
     *
     * Expected header format:
     * ```
     * Authorization: HMAC <signature>
     * ```
     *
     * Used to ensure request integrity and authenticate messages via cryptographic signatures.
     */
    HMAC(scheme = "HMAC"),

    /**
     * Basic authentication using base64-encoded username and password credentials.
     *
     * Expected header format:
     * ```
     * Authorization: Basic <base64_encoded_credentials>
     * ```
     *
     * Often used for simple authentication or legacy system compatibility.
     */
    BASIC(scheme = "Basic"),

    NONE(scheme = "None")
}