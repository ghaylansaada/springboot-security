package io.ghaylan.springboot.security

import io.ghaylan.springboot.security.annotations.AuthorizedEndpoint
import io.ghaylan.springboot.security.annotations.InternalEndpoint
import io.ghaylan.springboot.security.annotations.PublicEndpoint
import io.ghaylan.springboot.security.model.AuthScheme
import io.ghaylan.springboot.security.model.role.RoleAccessPolicy
import io.ghaylan.springboot.security.model.role.RoleAccessScope
import io.ghaylan.springboot.security.ratelimit.RateLimited
import io.ghaylan.springboot.security.extractor.AbstractAuthExtractor
import io.ghaylan.springboot.security.model.SecuritySchema
import io.ghaylan.springboot.security.ratelimit.RateLimitManager
import io.ghaylan.springboot.security.utils.EndpointsFinder
import jakarta.annotation.PostConstruct
import org.apache.commons.logging.LogFactory
import org.springframework.context.ApplicationContext
import org.springframework.http.HttpMethod
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.util.AntPathMatcher
import java.lang.reflect.Method

/**
 * Central security container that manages endpoint security configurations and validation.
 *
 * This class is the **runtime authority** for endpoint-level security. It inspects
 * controller methods at startup, validates security annotations, resolves permissions
 * and roles, and constructs [SecuritySchema] definitions for every HTTP endpoint.
 *
 * ## Responsibilities
 * - **Endpoint Discovery**: Scans controllers using [EndpointsFinder] at application startup.
 * - **Annotation Validation**: Enforces correct use of [PublicEndpoint], [InternalEndpoint],
 *   and [AuthorizedEndpoint] (exactly one must be present).
 * - **Role & Permission Resolution**: Uses [AuthDescriptor] to resolve required roles and permissions
 *   for annotated methods.
 * - **Schema Construction**: Caches a [SecuritySchema] per endpoint for fast lookup at runtime.
 * - **Rate Limiting**: Captures metadata from [RateLimited] annotations.
 * - **Pattern Matching**: Supports exact and Ant-style path patterns for flexible routing.
 *
 * ## Security Model
 * - **Public Endpoints** → No authentication required; mapped to a PUBLIC role in [AuthDescriptor].
 * - **Internal Endpoints** → Restricted to internal roles (scope = [RoleAccessScope.INTERNAL]).
 * - **Authorized Endpoints** → Require explicit auth schemes (e.g., BEARER, API_KEY).
 *   Their permissions and roles are resolved dynamically via [AuthDescriptor].
 *
 * @param RoleT Enum type implementing [RoleAccessPolicy]
 * @param PermissionT Enum type representing permissions
 */
open class SecurityContainer<RoleT, PermissionT>(
    private val appContext: ApplicationContext,
    val authExtractors : List<AbstractAuthExtractor>,
    val authDescriptor : AuthDescriptor<*, RoleT, PermissionT>,
    val rateLimitManager: RateLimitManager?,
) where RoleT: Enum<RoleT>, RoleT : RoleAccessPolicy, PermissionT: Enum<PermissionT>
{
    private val matcher = AntPathMatcher()
    private val logger = LogFactory.getLog(this.javaClass)
    private val _schemas = mutableListOf<SecuritySchema<RoleT, PermissionT>>()
    val schemas : List<SecuritySchema<RoleT, PermissionT>> get() = _schemas


    @PostConstruct
    private fun initialize()
    {
        val predefinedSchema = authDescriptor.provideAdditionalSchemas()

        _schemas.addAll(predefinedSchema)

         EndpointsFinder.find(appContext) { method, endpoint ->

             if (predefinedSchema.any { it.method == endpoint.first && matcher.match(it.uri, endpoint.second) })
             {
                 return@find
             }

             getSecuritySpecs(
                 method = method,
                 httpMethod = endpoint.first,
                 uri = endpoint.second
             ).apply { _schemas.add(this) }
        }

        logger.info("SecuritySchemaCache built with ${_schemas.size} secured endpoints")

        SecurityConfigValidation.validateRequiredBeans(appContext, this)
    }


    /**
     * Builds the [SecuritySchema] for a controller method.
     *
     * Validation rules:
     * - Endpoint must be annotated with exactly **one** of: [PublicEndpoint], [InternalEndpoint], [AuthorizedEndpoint].
     * - For [InternalEndpoint], an INTERNAL role must exist in [AuthDescriptor].
     * - For [PublicEndpoint], a PUBLIC role must exist in [AuthDescriptor].
     * - For [AuthorizedEndpoint]:
     *   - Must declare at least one [AuthScheme].
     *   - If using BEARER or API_KEY, roles/permissions must be resolved via [AuthDescriptor].
     *
     * @throws IllegalStateException If annotations are missing, duplicated, or misconfigured.
     */
    private fun getSecuritySpecs(
        method : Method,
        httpMethod : HttpMethod,
        uri : String,
    ) : SecuritySchema<RoleT, PermissionT>
    {
        val rateLimit = method.getAnnotation(RateLimited::class.java)

        val internalEndpoint = method.getAnnotation(InternalEndpoint::class.java)
        val authorizedEndpoint = method.getAnnotation(AuthorizedEndpoint::class.java)
        val publicEndpointAnnotation = method.getAnnotation(PublicEndpoint::class.java)

        val totalAnnotations = listOfNotNull(
            internalEndpoint,
            authorizedEndpoint,
            publicEndpointAnnotation
        ).size

        val methodSignature = "${method.declaringClass.name}#${method.name} -> $httpMethod $uri"

        require(totalAnnotations == 1) {
            "Invalid configuration: $methodSignature must be annotated with exactly ONE of @PublicEndpoint, @InternalEndpoint, or @AuthorizedEndpoint. Found $totalAnnotations."
        }

        if (internalEndpoint != null)
        {
            val roleInternal = authDescriptor.allRoles.find { it.scope == RoleAccessScope.INTERNAL }

            requireNotNull(roleInternal) {
                "Missing INTERNAL role in AuthDescriptor. Endpoint $methodSignature is annotated with @InternalEndpoint but no role with scope=INTERNAL is defined."
            }

            return SecuritySchema(
                method = httpMethod,
                uri = uri,
                authSchemes = setOf(AuthScheme.BEARER),
                permissions = emptySet(),
                roles = setOf(roleInternal),
                accessScope = RoleAccessScope.INTERNAL,
                rateLimit = rateLimit)
        }

        if (publicEndpointAnnotation != null)
        {
            val rolePublic = authDescriptor.allRoles.find { it.scope == RoleAccessScope.PUBLIC }

            requireNotNull(rolePublic) {
                "Missing PUBLIC role in AuthDescriptor. Endpoint $methodSignature is annotated with @PublicEndpoint but no role with scope=PUBLIC is defined."
            }

            return SecuritySchema(
                method = httpMethod,
                uri = uri,
                authSchemes = setOf(),
                permissions = emptySet(),
                roles = setOf(rolePublic),
                accessScope = RoleAccessScope.PUBLIC,
                rateLimit = rateLimit)
        }

        if (authorizedEndpoint != null)
        {
            require(authorizedEndpoint.schemes.isNotEmpty()) {
                "Invalid configuration: $methodSignature uses @AuthorizedEndpoint but does not specify any AuthScheme. Provide at least one (e.g., AuthScheme.BEARER, AuthScheme.API_KEY)."
            }

            val authorizationSpecs = SecuritySchema<RoleT, PermissionT>(
                method = httpMethod,
                uri = uri,
                authSchemes = authorizedEndpoint.schemes.toSet(),
                permissions = emptySet(),
                roles = authDescriptor.allRoles.filter { it.scope == RoleAccessScope.SECURED }.toSet(),
                accessScope = RoleAccessScope.SECURED,
                rateLimit = rateLimit)

            if (authorizedEndpoint.schemes.any { it == AuthScheme.BEARER || it == AuthScheme.API_KEY })
            {
                // Process custom security annotations via the AuthDescriptor
                // This allows applications to define their own security annotations
                val jwtSpecs = authDescriptor.resolveAuthorizationRequirements(method.annotations)

                require(jwtSpecs.first.isNotEmpty() || jwtSpecs.second.isNotEmpty()) {
                    "Misconfigured @AuthorizedEndpoint at $methodSignature. No roles or permissions resolved from AuthDescriptor. Ensure your AuthDescriptor correctly maps annotations to roles/permissions."
                }

                return authorizationSpecs.copy(permissions = jwtSpecs.first, roles = jwtSpecs.second)
            }

            return authorizationSpecs
        }

        throw IllegalStateException("Endpoint $methodSignature is misconfigured. @AuthorizedEndpoint requires at least one valid AuthScheme (e.g., BEARER or API_KEY).")
    }


    /**
     * Finds the [SecuritySchema] that applies to the given HTTP request.
     *
     * This function extracts the URI path and HTTP method from the [request]
     * and delegates the lookup to [findByRequest].
     *
     * @param request Incoming HTTP request.
     * @return Matching [SecuritySchema], or null if no matching schema is found.
     */
    fun findByRequest(request : ServerHttpRequest) : SecuritySchema<*, *>?
    {
        return findByRequest(uri = request.uri.path, method = request.method.name())
    }


    /**
     * Finds the [SecuritySchema] that matches the specified URI and HTTP method.
     *
     * Matching strategy:
     * 1. Tries an exact URI match with the same HTTP method (fast path).
     * 2. If no exact match is found, attempts an Ant-style pattern match.
     *
     * @param uri The request URI path to match.
     * @param method The HTTP method to match (e.g., "GET", "POST").
     * @return Matching [SecuritySchema], or null if no match exists.
     */
    fun findByRequest(
        uri : String,
        method : String,
    ) : SecuritySchema<*, *>?
    {
        // Try exact match first, then pattern match in one pass
        var fallback: SecuritySchema<*, *>? = null

        for (schema in schemas)
        {
            if (schema.method.name() != method) continue

            if (schema.uri == uri) return schema

            if (fallback == null && matcher.match(schema.uri, uri))
            {
                fallback = schema
            }
        }
        return fallback
    }


    /**
     * Collects all distinct [AuthScheme] values that are used across
     * the configured security schemas.
     *
     * - Automatically includes [AuthScheme.BEARER] if at least one
     *   endpoint uses [RoleAccessScope.INTERNAL], since internal access
     *   always requires bearer-based authentication.
     * - Stops early if all possible [AuthScheme] values are already found.
     *
     * @return List of all unique [AuthScheme] values in use.
     */
    fun collectUsedSecuritySchemes() : List<AuthScheme>
    {
        val schemes = mutableSetOf<AuthScheme>()

        val totalSchemes = AuthScheme.entries.size

        for (schema in schemas)
        {
            schemes.addAll(schema.authSchemes)

            if (schema.accessScope == RoleAccessScope.INTERNAL) {
                schemes.add(AuthScheme.BEARER)
            }

            if (schemes.size == totalSchemes) break
        }

        return schemes.toList()
    }


    /**
     * Checks if any endpoint is protected using the [AuthScheme.HMAC] scheme.
     *
     * Useful for conditionally enabling HMAC signature filters only if required.
     *
     * @return `true` if at least one endpoint uses HMAC authentication, `false` otherwise.
     */
    fun hasSchemeHMAC() : Boolean
    {
        return schemas.any {
            it.authSchemes.contains(AuthScheme.HMAC)
        }
    }


    /**
     * Returns whether at least one endpoint is annotated with [RateLimited].
     *
     * This allows conditional activation of rate limiting filters only
     * if the application actually uses rate limiting.
     *
     * @return `true` if at least one endpoint has a [RateLimited] annotation, otherwise `false`.
     */
    fun hasRateLimiter() : Boolean
    {
        return schemas.any { it.rateLimit != null }
    }
}