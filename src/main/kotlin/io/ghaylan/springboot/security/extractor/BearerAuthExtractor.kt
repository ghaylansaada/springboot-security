package io.ghaylan.springboot.security.extractor

import io.ghaylan.springboot.security.exception.HttpStatusCode
import io.ghaylan.springboot.security.exception.SecurityViolationException
import io.ghaylan.springboot.security.model.AuthScheme
import io.ghaylan.springboot.security.utils.jwt.UserJwtReader
import io.ghaylan.springboot.security.utils.jwt.SystemJwtManager
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.security.SignatureException
import org.springframework.http.server.reactive.ServerHttpRequest

/**
 * JWT Bearer token authentication extractor for user and system authentication.
 *
 * This extractor validates JWT tokens for both user authentication and internal system
 * communication. It supports two modes of operation:
 * - **User Authentication**: Validates user JWT tokens for regular API access
 * - **System Authentication**: Validates internal JWT tokens for system-to-system communication
 *
 * ## Security Features
 * - **JWT Validation**: Comprehensive JWT token validation including signature, expiration, and claims
 * - **Dual Mode Support**: Handles both user and system authentication tokens
 * - **Exception Handling**: Provides specific error messages for different JWT validation failures
 * - **Audience Validation**: Validates token audience for system tokens
 * - **URI Validation**: Validates request URI matches token claims for system tokens
 *
 * ## Token Types
 * - **User Tokens**: Regular JWT tokens for authenticated users
 * - **System Tokens**: Internal JWT tokens for system communication (requires INTERNAL scope)
 *
 * ## Request Format
 * ```
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * ```
 *
 * ## Usage in Consumer Projects
 * ```kotlin
 * @Bean
 * fun bearerAuthExtractor(
 *     userJwtReader: UserJwtReader,
 *     systemJwtManager: systemJwtManager<UserRole>
 * ): BearerAuthExtractor = BearerAuthExtractor(userJwtReader, systemJwtUtils)
 * ```
 *
 * ## Error Handling
 * The extractor provides specific error messages for different JWT validation scenarios:
 * - **ExpiredJwtException**: Token has expired
 * - **SignatureException**: Token signature is invalid or tampered
 * - **MalformedJwtException**: Token structure is incorrect
 * - **UnsupportedJwtException**: Token type or claims not supported
 * - **IllegalArgumentException**: Malformed or missing JWT
 *
 * @param userJwtReader Utility for reading and validating user JWT tokens
 * @param systemJwtManager Utility for generating and validating system JWT tokens
 */
class BearerAuthExtractor(
    private val userJwtReader : UserJwtReader,
    private val systemJwtManager: SystemJwtManager<*>
) : AbstractAuthExtractor(AuthScheme.BEARER)
{

    override suspend fun extractAuthentication(
        request: ServerHttpRequest,
        credentials: String,
        isInternalRequest: Boolean,
        rawRequestBody: String?
    ) : RawExtractedAuth
    {
        return try
        {
            if (isInternalRequest)
            {
                systemJwtManager.resolve(
                    jwt = credentials,
                    requestMethod = request.method.name(),
                    requestUri = request.uri.path)!!
            }
            else userJwtReader.resolve(credentials)!!
        }
        catch (exception : SecurityViolationException) {
            throw exception
        }
        catch (_: NullPointerException) {
            // Token is null (likely missing Authorization header or value)
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: JWT is required.")
        }
        catch (_: IllegalArgumentException) {
            // Token is an empty string or improperly passed
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: malformed or missing JWT.")
        }
        catch (e: ExpiredJwtException) {
            // Token is valid but expired
            throw SecurityViolationException(HttpStatusCode.EXPIRED_TOKEN, "Authentication failed: JWT expired at: ${e.claims?.expiration}, please refresh your token or log in again.")
        }
        catch (_: SignatureException) {
            // Token's signature is invalid or tampered
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: JWT verification failed.")
        }
        catch (_: MalformedJwtException) {
            // Token structure is incorrect (not in JWT format)
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: malformed JWT format.")
        }
        catch (_: UnsupportedJwtException) {
            // Token type or claims isn't supported
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: unsupported authentication JWT type or claims.")
        }
        catch (_: JwtException) {
            // Any other JWT-related exception
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: invalid JWT.")
        }
    }
}