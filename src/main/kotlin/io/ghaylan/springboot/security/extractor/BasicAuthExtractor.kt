package io.ghaylan.springboot.security.extractor

import io.ghaylan.springboot.security.exception.HttpStatusCode
import io.ghaylan.springboot.security.exception.SecurityViolationException
import io.ghaylan.springboot.security.model.AuthScheme
import org.springframework.http.server.reactive.ServerHttpRequest
import java.util.Base64

/**
 * HTTP Basic Authentication extractor for username/password authentication.
 *
 * This extractor handles traditional HTTP Basic Authentication by decoding Base64-encoded
 * credentials and validating them against a user resolver. It's suitable for simple
 * authentication scenarios and legacy system integration.
 *
 * ## Security Features
 * - **Base64 Decoding**: Decodes Base64-encoded username:password pairs
 * - **Credential Validation**: Validates credentials through configurable user resolver
 * - **Format Validation**: Ensures proper username:password format
 * - **Error Handling**: Provides specific error messages for different validation failures
 *
 * ## Request Format
 * The Basic authorization header should follow this format:
 * ```
 * Authorization: Basic base64(username:password)
 * ```
 *
 * ## Security Considerations
 * - **HTTPS Required**: Basic authentication should only be used over HTTPS
 * - **Credential Exposure**: Credentials are sent with every request
 * - **No Token Management**: No built-in token expiration or refresh mechanisms
 * - **Legacy Support**: Primarily for legacy system integration
 *
 * ## Usage in Consumer Projects
 * ```kotlin
 * @Bean
 * fun basicAuthExtractor(userService: UserService): BasicAuthExtractor {
 *     return BasicAuthExtractor { username, password ->
 *         // Validate credentials against your data source
 *         userService.authenticate(username, password)?.let { user ->
 *             RawExtractedAuth(
 *                 id = user.id,
 *                 role = user.role.name,
 *                 name = user.name,
 *                 tokenType = null,
 *                 credentials = null,
 *                 details = user.details)
 *         }
 *     }
 * }
 * ```
 *
 * ## Error Scenarios
 * - **Invalid Base64**: Malformed Base64 encoding in authorization header
 * - **Invalid Format**: Missing colon separator in username:password format
 * - **Invalid Credentials**: Username or password not found or incorrect
 *
 * @param userResolver Function that validates username and password credentials
 */
class BasicAuthExtractor(
    private val userResolver: suspend (username: String, password: String) -> RawExtractedAuth?
) : AbstractAuthExtractor(AuthScheme.BASIC)
{

    override suspend fun extractAuthentication(
        request: ServerHttpRequest,
        credentials: String,
        isInternalRequest: Boolean,
        rawRequestBody: String?
    ) : RawExtractedAuth
    {
        val decoded = runCatching {
            String(Base64.getDecoder().decode(credentials))
        }.getOrElse {
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: invalid Base64 encoding in Basic Authorization header.")
        }

        val (username, password) = decoded.split(":", limit = 2).takeIf { it.size == 2 }
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: invalid Basic credentials format in Basic Authorization header, expected 'username:password'.")

        return userResolver(username, password)
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: invalid username or password in Basic Authorization header.")
    }
}