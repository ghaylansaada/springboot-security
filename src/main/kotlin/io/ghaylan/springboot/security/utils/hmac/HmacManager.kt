package io.ghaylan.springboot.security.utils.hmac

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC (Hash-based Message Authentication Code) utility manager.
 *
 * This class provides functionality for generating and validating HMAC-SHA256 signatures
 * for API requests. It ensures request integrity, authentication, and protection against
 * replay attacks by including timestamp validation and canonical request strings.
 *
 * ## Security Features
 * - **HMAC-SHA256 Signing**: Creates cryptographically secure signatures.
 * - **Canonical Request Strings**: Standardizes requests to ensure consistent signing.
 * - **Body Hashing**: Computes SHA-256 hash of the request body for tamper detection.
 * - **Clock Skew Tolerance**: Configurable allowance for timestamp differences.
 * - **Base64 Encoding**: Encodes signatures in Base64 for transmission over HTTP headers.
 *
 * ## Canonical Request Structure
 * Each request string used for signing includes the following, separated by newline characters:
 * 1. HTTP method (e.g., GET, POST, PUT, DELETE)
 * 2. Full request path with query parameters
 * 3. SHA-256 hash of the request body
 * 4. UTC timestamp in ISO format (yyyyMMdd'T'HHmmssZ)
 *
 * ## Example Usage
 * ```kotlin
 * val hmacManager = HmacManager(maxClockSkew = 5)
 *
 * val path = hmacManager.buildRequestPathWithQuery("/api/users", "page=1&limit=10")
 * val body = """{"name":"John","role":"ADMIN"}"""
 * val timestamp = "20250820T081000Z"
 * val signature = hmacManager.generateHmacSignature(
 *     secretKey = "superSecretKey",
 *     method = "POST",
 *     path = path,
 *     body = body,
 *     timestamp = timestamp)
 * ```
 *
 * ## Security Considerations
 * - Ensure secret keys are securely stored and rotated periodically.
 * - Maintain synchronized system clocks to avoid rejected requests.
 * - Validate timestamps to prevent replay attacks using `maxClockSkew`.
 * - Include request body in signature to detect tampering.
 *
 * @param maxClockSkew The maximum allowed clock skew in minutes. Must be non-negative (default: 5).
 */
class HmacManager(val maxClockSkew : Long)
{
    companion object
    {
        private const val HMAC_ALGORITHM = "HmacSHA256"
        const val AUTH_KEY_API_KEY = "apiKey"
        const val AUTH_KEY_SIGNATURE = "signature"
        const val AUTH_KEY_TIMESTAMP = "timestamp"
        val TIMESTAMP_FORMATTER : DateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmssX").withZone(
            ZoneOffset.UTC)
    }


    init
    {
        require(maxClockSkew >= 0) { "maxClockSkew must be >= 0" }
    }


    /**
     * Generates a Base64-encoded HMAC-SHA256 signature for a canonical request string.
     *
     * The canonical string format is:
     * ```
     * HTTP_METHOD\n
     * REQUEST_PATH_WITH_QUERY\n
     * SHA256_BODY_HASH\n
     * TIMESTAMP
     * ```
     *
     * @param secretKey Secret key used for HMAC signing. Must not be blank.
     * @param method HTTP method (GET, POST, etc.) of the request.
     * @param path Full request path including query parameters.
     * @param body Raw request body as a string.
     * @param timestamp UTC timestamp string included in the request.
     * @return Base64-encoded HMAC-SHA256 signature.
     */
    fun generateSignature(
        secretKey : String,
        method : String,
        path : String,
        body : String,
        timestamp : String
    ) : String
    {
        val canonicalString = "$method\n$path\n${hashBody(body)}\n$timestamp"
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(secretKey.toByteArray(), HMAC_ALGORITHM))
        val rawHmac = mac.doFinal(canonicalString.toByteArray())
        return Base64.getEncoder().encodeToString(rawHmac)
    }


    /**
     * Builds a full request path including query parameters (if provided).
     *
     * Trailing slashes in the URI are removed for consistency. Query parameters
     * are appended if not blank.
     *
     * @param uri Request URI path (e.g., "/api/users").
     * @param query Optional query string (e.g., "page=1&limit=10").
     * @return Canonicalized full request path with query parameters.
     */
    fun buildRequestPathWithQuery(
        uri : String,
        query : String?
    ) : String
    {
        val path = uri.trimEnd('/')

        if (query.isNullOrBlank()) return path

        val sortedQuery = query.split("&")
            .map { it.split("=", limit = 2) }
            .sortedBy { it[0] }
            .joinToString("&") {
                val key = it[0].encodeURLComponent()
                val value = it.getOrNull(1)?.encodeURLComponent() ?: ""
                "$key=$value"
            }

        return "$path?$sortedQuery"
    }


    /** Extension to encode RFC 3986 style */
    private fun String.encodeURLComponent(): String
    {
        return java.net.URLEncoder.encode(this, "UTF-8")
            .replace("+", "%20")
            .replace("*", "%2A")
            .replace("%7E", "~")
    }


    /**
     * Computes the SHA-256 hash of the request body.
     *
     * The result is returned as a lowercase hexadecimal string.
     * Used for signing to ensure request integrity.
     *
     * @param body Raw request body as a string.
     * @return SHA-256 hash of the body in hex format.
     */
    fun hashBody(body : String) : String
    {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(body.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }
}