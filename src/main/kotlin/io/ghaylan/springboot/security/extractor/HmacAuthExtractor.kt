package io.ghaylan.springboot.security.extractor

import io.ghaylan.springboot.security.exception.HttpStatusCode
import io.ghaylan.springboot.security.exception.SecurityViolationException
import io.ghaylan.springboot.security.utils.hmac.HmacManager
import io.ghaylan.springboot.security.model.AuthScheme
import org.springframework.http.server.reactive.ServerHttpRequest
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant

/**
 * HMAC-based authentication extractor for request signing and integrity verification.
 *
 * This extractor validates HMAC signatures to ensure request authenticity and integrity.
 * It supports the HMAC-SHA256 algorithm and provides protection against replay attacks
 * through timestamp validation.
 *
 * ## Security Features
 * - **Request Signing**: Validates HMAC-SHA256 signatures of request data
 * - **Replay Protection**: Validates request timestamps to prevent replay attacks
 * - **Clock Skew Tolerance**: Configurable tolerance for clock differences between client and server
 * - **Constant-Time Comparison**: Uses constant-time signature comparison to prevent timing attacks
 *
 * ## Request Format
 * The HMAC authorization header should follow this format:
 * ```
 * Authorization: HMAC apiKey=your-api-key,signature=base64-signature,timestamp=yyyyMMddTHHmmssZ
 * ```
 *
 * ## Signature Generation
 * The signature is generated from a canonical string containing:
 * - HTTP method (GET, POST, etc.)
 * - Request path with query parameters
 * - SHA-256 hash of request body
 * - Timestamp in UTC format
 *
 * ## Usage in Consumer Projects
 * ```kotlin
 * @Bean
 * fun hmacAuthExtractor(hmacManager: HmacManager, userService: UserService): HmacAuthExtractor {
 *     return HmacAuthExtractor(hmacManager) { apiKey ->
 *         // Resolve user from your data source
 *         userService.findByApiKey(apiKey)?.let { user ->
 *             RawExtractedAuth(
 *                 id = user.id,
 *                 role = user.role.name,
 *                 name = user.name,
 *                 permissions = null,
 *                 credentials = user.secretKey,
 *                 details = user.details)
 *         }
 *     }
 * }
 * ```
 *
 * @param hmacManager Utility class for HMAC signature generation and validation
 * @param userResolver Function that resolves the user associated with the public API key
 */
class HmacAuthExtractor(
    private val hmacManager : HmacManager,
    private val userResolver : suspend (apiKey : String) -> RawExtractedAuth?
) : AbstractAuthExtractor(AuthScheme.HMAC)
{

    override suspend fun extractAuthentication(
        request: ServerHttpRequest,
        credentials: String,
        isInternalRequest: Boolean,
        rawRequestBody: String?
    ) : RawExtractedAuth
    {
        val params = parseHmacAuthorizationHeader(credentials)

        val apiKey = params[HmacManager.AUTH_KEY_API_KEY]?.ifBlank { null }
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: missing '${HmacManager.AUTH_KEY_API_KEY}' in HMAC Authorization header.")

        val userSignature = params[HmacManager.AUTH_KEY_SIGNATURE]?.ifBlank { null }
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: missing '${HmacManager.AUTH_KEY_SIGNATURE}' in HMAC Authorization header.")

        val timestamp = params[HmacManager.AUTH_KEY_TIMESTAMP]?.ifBlank { null }
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: missing '${HmacManager.AUTH_KEY_TIMESTAMP}' in HMAC Authorization header.")

        val user = userResolver(apiKey)
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: unknown apiKey in HMAC Authorization header.")

        if (user.credentials.isNullOrBlank())
        {
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: user credentials not found for apiKey in HMAC Authorization header.")
        }

        validateTimestamp(timestamp)

        val expectedSignature = hmacManager.generateSignature(
            secretKey = user.credentials,
            method = request.method.name(),
            path = hmacManager.buildRequestPathWithQuery(uri = request.uri.path, query = request.uri.rawQuery),
            body = rawRequestBody ?: "",
            timestamp = timestamp
        ).toByteArray()

        if (!MessageDigest.isEqual(expectedSignature, userSignature.toByteArray()))
        {
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: calculated signature does not match provided signature in HMAC Authorization header.")
        }

        return user
    }


    /**
     * Validates that the timestamp is within the accepted range to prevent replay attacks.
     */
    private fun validateTimestamp(timestamp : String)
    {
        val requestInstant: Instant = runCatching {
            Instant.from(HmacManager.TIMESTAMP_FORMATTER.parse(timestamp))
        }.getOrElse {
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: invalid timestamp format: expected 'yyyyMMdd'T'HHmmss'Z', got '$timestamp' in HMAC Authorization header.")
        }

        val now = Instant.now()

        val skew = Duration.between(requestInstant, now).abs()

        if (skew > Duration.ofMinutes(hmacManager.maxClockSkew))
        {
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: request timestamp '$timestamp' is expired or too far in the future. Maximum allowed clock skew is ${hmacManager.maxClockSkew} minutes in HMAC Authorization header.")
        }
    }


    /**
     * Parses the HMAC Authorization header and extracts its key-value pairs.
     */
    private fun parseHmacAuthorizationHeader(authorization : String): Map<String, String>
    {
        return authorization
            .removePrefix(supportedScheme.scheme)
            .trim()
            .split(",")
            .mapNotNull { part ->
                val keyValue = part.split("=", limit = 2)
                if (keyValue.size == 2)
                {
                    val key = keyValue[0].trim()
                    val value = keyValue[1].trim()
                    if (key.isNotEmpty() && value.isNotEmpty()) key to value else null
                }
                else null
            }.toMap()
    }
}