package io.ghaylan.springboot.security.extractor

import io.ghaylan.springboot.security.exception.HttpStatusCode
import io.ghaylan.springboot.security.exception.SecurityViolationException
import io.ghaylan.springboot.security.utils.apikey.ApiKeyManager
import io.ghaylan.springboot.security.model.AuthScheme
import org.springframework.http.server.reactive.ServerHttpRequest
import java.time.Instant

/**
 * API Key-based authentication extractor for service-to-service communication.
 *
 * This extractor validates API keys by decrypting them and checking their expiration.
 * It's designed for service-to-service authentication and API access scenarios where
 * long-lived credentials are appropriate.
 *
 * ## Security Features
 * - **API Key Validation**: Validates API key format and prefix
 * - **Decryption**: Decrypts API keys using AES-GCM encryption
 * - **Expiration Checking**: Validates API key expiration timestamps
 * - **User Resolution**: Resolves users from API keys through configurable resolver
 * - **Secure Storage**: API keys are encrypted and contain user information
 *
 * ## Request Format
 * The API Key authorization header should follow this format:
 * ```
 * Authorization: ApiKey your-encrypted-api-key
 * ```
 *
 * ## API Key Structure
 * API keys are encrypted and contain:
 * - User ID
 * - User role
 * - Expiration timestamp
 * - Service-specific prefix
 *
 * ## Security Considerations
 * - **Long-lived Credentials**: API keys can have extended expiration periods
 * - **Service-to-Service**: Primarily designed for service communication
 * - **Encrypted Storage**: API keys contain encrypted user information
 * - **Prefix Validation**: Ensures API keys belong to the correct service
 *
 * ## Usage in Consumer Projects
 * ```kotlin
 * @Bean
 * fun apiKeyAuthExtractor(
 *     apiKeyManager: ApiKeyManager,
 *     userRepository: UserRepository
 * ): ApiKeyAuthExtractor {
 *     return ApiKeyAuthExtractor(apiKeyManager) { apiKey ->
 *         // Resolve user from your data source
 *         userRepository.findByApiKey(apiKey)?.let { user ->
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
 * ## Error Scenarios
 * - **Unknown API Key**: API key not found in user resolver
 * - **Missing Credentials**: User credentials not available for decryption
 * - **Expired API Key**: API key has passed its expiration timestamp
 * - **Invalid Format**: API key doesn't match expected format or prefix
 *
 * @param apiKeyManager Utility class for API key generation and decryption
 * @param userResolver Function that resolves the user associated with the API key
 */
class ApiKeyAuthExtractor(
    private val apiKeyManager : ApiKeyManager,
    private val userResolver : suspend (apiKey : String) -> RawExtractedAuth?
) : AbstractAuthExtractor(AuthScheme.API_KEY)
{

    override suspend fun extractAuthentication(
        request: ServerHttpRequest,
        credentials: String,
        isInternalRequest: Boolean,
        rawRequestBody: String?
    ) : RawExtractedAuth
    {
        val user = userResolver.invoke(credentials)
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: unknown API key.")

        if (user.credentials.isNullOrBlank())
        {
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: user credentials not found for API key.")
        }

        val decryptedApiKey = apiKeyManager.decryptApiKey(apiKey = credentials, secret = user.credentials)

        if (decryptedApiKey.expiresAt.isBefore(Instant.now()))
        {
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: API key expired at: '${decryptedApiKey.expiresAt}'.")
        }

        return user
    }
}