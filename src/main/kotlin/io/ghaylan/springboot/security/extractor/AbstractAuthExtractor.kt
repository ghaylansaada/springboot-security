package io.ghaylan.springboot.security.extractor

import io.ghaylan.springboot.security.AuthDescriptor
import io.ghaylan.springboot.security.exception.HttpStatusCode
import io.ghaylan.springboot.security.exception.SecurityViolationException
import io.ghaylan.springboot.security.model.AuthScheme
import io.ghaylan.springboot.security.model.GenericAuthentication
import io.ghaylan.springboot.security.model.role.RoleAccessPolicy
import io.ghaylan.springboot.security.model.role.RoleAccessScope
import io.ghaylan.springboot.security.utils.ReactiveRequestUtils.extractAuthorizationHeader
import io.ghaylan.springboot.security.utils.ReactiveRequestUtils.extractCredentials
import io.ghaylan.springboot.security.utils.ReactiveRequestUtils.extractIpAddress
import io.ghaylan.springboot.security.utils.ReactiveRequestUtils.extractRequestId
import io.ghaylan.springboot.security.utils.ReactiveRequestUtils.extractSecretCode
import io.ghaylan.springboot.security.utils.ReactiveRequestUtils.extractUserAgent
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.web.server.ServerWebExchange
import java.time.Instant
import java.util.Locale

/**
 * Abstract base class for reactive authentication extractors.
 *
 * This class provides a unified interface for extracting and validating authentication
 * information from reactive HTTP requests using Kotlin coroutines. It serves as the
 * foundation for reactive versions of concrete extractors (Bearer, API Key, HMAC, Basic).
 *
 * ## Available Concrete Extractors
 * - [BearerAuthExtractor]: Handles JWT Bearer token authentication
 * - [ApiKeyAuthExtractor]: Handles API key authentication
 * - [HmacAuthExtractor]: Handles HMAC signature authentication
 * - [BasicAuthExtractor]: Handles Basic authentication
 *
 * ## Responsibilities
 * - Extract authentication credentials from reactive requests
 * - Validate authentication tokens and credentials asynchronously
 * - Convert raw authentication data to standardized format
 * - Handle anonymous user creation for public endpoints
 * - Extract request metadata (headers, parameters, IP, etc.) reactively
 *
 * ## User Resolution
 * When implementing concrete extractors as beans in consumer projects, you must provide
 * user resolution logic to fetch user information from your data source (database, proxy,
 * in-memory store, etc.). This is typically done in the `extractAuthentication` method
 * of the concrete extractor implementation as a suspending function.
 *
 * ## Important Notes
 * - **Suspend functions**: All authentication operations are suspending functions
 * - **Non-blocking**: Designed to work with reactive data sources
 * - **User data source**: When implementing concrete extractors, provide the necessary
 *   reactive data source configuration for fetching user information.
 * - **JWT security**: When using JWT for both user authentication and internal communication,
 *   use different private keys for security purposes.
 *
 * ## Usage in Consumer Projects
 * ```kotlin
 * @Bean
 * suspend fun reactiveBearerAuthExtractor(
 *     jwtReader: ReactiveJwtReader,
 *     userService: ReactiveUserService
 * ): ReactiveBearerAuthExtractor {
 *     return ReactiveBearerAuthExtractor(jwtReader, userService)
 * }
 * ```
 *
 * @param supportedScheme The authentication scheme this extractor handles
 */
abstract class AbstractAuthExtractor(val supportedScheme: AuthScheme)
{

    /**
     * Extracts and validates authentication for an authenticated user using coroutines.
     *
     * This method processes the request to extract authentication credentials,
     * validates them according to the supported scheme, and returns a complete
     * authentication object with user information and request metadata.
     *
     * @param exchange The reactive HTTP request containing authentication information
     * @param isInternalRequest Whether this is an internal system request
     * @param authDescriptor Project-specific authentication descriptor
     * @return Complete authentication object with user and request information
     * @throws SecurityViolationException if authentication fails or is missing
     */
    suspend fun <RoleT, PermissionT> extractAuthenticatedUser(
        exchange: ServerWebExchange,
        isInternalRequest: Boolean,
        authDescriptor: AuthDescriptor<*, RoleT, PermissionT>,
        rawRequestBody: String?
    ) : GenericAuthentication<RoleT, PermissionT, GenericAuthentication.User<RoleT, PermissionT>> where RoleT : Enum<RoleT>, RoleT : RoleAccessPolicy, PermissionT : Enum<PermissionT>
    {
        val request = exchange.request

        request.extractAuthorizationHeader()
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: missing Authorization header")

        val credentials = request.extractCredentials(supportedScheme.scheme)
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: missing credentials in Authorization header")

        val extractedAuth = extractAuthentication(
            request = request,
            credentials = credentials,
            isInternalRequest = isInternalRequest,
            rawRequestBody = rawRequestBody)

        val headerInfo = extractHeaderInfo(request, credentials, supportedScheme)

        val authenticatedUser = GenericAuthentication.User(
            id = extractedAuth.id,
            name = extractedAuth.name,
            role = resolveUserRole(extractedAuth.role, authDescriptor),
            permissions = resolvePermissions(extractedAuth.permissions ?: emptyList(), authDescriptor))

        for (entry in extractedAuth.entries) {
            authenticatedUser.putIfAbsent(entry.key, entry.value)
        }

        return GenericAuthentication(
            user = authenticatedUser,
            locale = exchange.localeContext.locale ?: Locale.getDefault(),
            header = headerInfo,
            ipAddress = request.extractIpAddress(),
            userAgent = request.extractUserAgent(),
            datetime = Instant.now())
    }


    /**
     * Creates an anonymous user for public endpoints.
     *
     * This method creates a standardized authentication object for unauthenticated
     * users accessing public endpoints, using the public role from the auth descriptor.
     *
     * @param exchange The reactive HTTP request
     * @param authDescriptor Project-specific authentication descriptor
     * @return Authentication object representing an anonymous user
     */
    fun <RoleT, PermissionT> createAnonymousUser(
        exchange: ServerWebExchange,
        authDescriptor: AuthDescriptor<*, RoleT, PermissionT>
    ): GenericAuthentication<RoleT, PermissionT, *> where RoleT : Enum<RoleT>, RoleT : RoleAccessPolicy, PermissionT : Enum<PermissionT>
    {
        val headerInfo = extractHeaderInfo(exchange.request, null, null)

        // Find the public role for anonymous access
        val publicRole = authDescriptor.allRoles.find { it.scope == RoleAccessScope.PUBLIC }
            ?: error("No PUBLIC role found in ${authDescriptor.roleClass.simpleName}")

        val anonymousUser = GenericAuthentication.User<RoleT, PermissionT>(
            id = "anonymous",
            role = publicRole,
            permissions = emptySet(),
            name = "Anonymous")

        return GenericAuthentication(
            user = anonymousUser,
            header = headerInfo,
            ipAddress = exchange.request.extractIpAddress(),
            userAgent = exchange.request.extractUserAgent(),
            locale = exchange.localeContext.locale ?: Locale.getDefault(),
            datetime = Instant.now())
    }


    /**
     * Extracts and validates authentication from the reactive request.
     *
     * This abstract method must be implemented by concrete extractors to handle
     * the specific authentication scheme validation logic. This is where user
     * resolution from reactive data sources should be implemented as a suspending function.
     *
     * @param request The reactive HTTP request to extract data from
     * @param credentials The extracted credentials from the Authorization header
     * @param isInternalRequest Whether this is an internal system request
     * @return Raw authentication data extracted from the request
     */
    protected abstract suspend fun extractAuthentication(
        request: ServerHttpRequest,
        credentials: String,
        isInternalRequest: Boolean,
        rawRequestBody: String?
    ) : RawExtractedAuth


    /**
     * Resolves a role string to the corresponding role enum value.
     *
     * @param roleString The role string from the authentication data
     * @param authDescriptor The authentication descriptor containing role definitions
     * @return The resolved role enum value
     * @throws SecurityViolationException if the role is invalid or missing
     */
    private fun <RoleT> resolveUserRole(
        roleString: String?,
        authDescriptor: AuthDescriptor<*, RoleT, *>
    ): RoleT where RoleT : Enum<RoleT>, RoleT : RoleAccessPolicy
    {
        return authDescriptor.allRoles.find {
            it.name == roleString
        } ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: user role is missing or invalid")
    }


    /**
     * Resolves permissions strings to the corresponding permission enum value.
     *
     * @param permissions The permissions as list of strings from the authentication data
     * @param authDescriptor The authentication descriptor containing permission definitions
     * @return The resolved permission enum values
     */
    private fun <PermissionT> resolvePermissions(
        permissions: List<String>,
        authDescriptor: AuthDescriptor<*, *, PermissionT>
    ) : Set<PermissionT> where PermissionT : Enum<PermissionT>
    {
        return authDescriptor.allPermissions.mapNotNull {
            if (permissions.contains(it.name)) it else null
        }.toSet()
    }


    /**
     * Extracts header information from the reactive request.
     *
     * @param request The reactive HTTP request containing headers
     * @param credentials The authorization credentials, if available
     * @param scheme The authentication scheme being used
     * @return Header information object
     */
    private fun extractHeaderInfo(
        request: ServerHttpRequest,
        credentials: String?,
        scheme: AuthScheme?
    ) : GenericAuthentication.HeaderInfo
    {
        return GenericAuthentication.HeaderInfo(
            authorization = credentials,
            authScheme = scheme,
            secretCode = request.extractSecretCode(),
            requestId = request.extractRequestId())
    }
}