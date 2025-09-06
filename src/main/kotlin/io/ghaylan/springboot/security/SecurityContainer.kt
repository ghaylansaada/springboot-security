package io.ghaylan.springboot.security

import io.ghaylan.springboot.security.annotations.InternalEndpoint
import io.ghaylan.springboot.security.annotations.PublicEndpoint
import io.ghaylan.springboot.security.model.AuthScheme
import io.ghaylan.springboot.security.model.role.RoleAccessPolicy
import io.ghaylan.springboot.security.model.role.RoleAccessScope
import io.ghaylan.springboot.security.ratelimit.RateLimited
import io.ghaylan.springboot.security.extractor.AbstractAuthExtractor
import io.ghaylan.springboot.security.model.SecuritySchema
import io.ghaylan.springboot.security.model.token.TokenAccessPolicy
import io.ghaylan.springboot.security.model.token.TokenAccessScope
import io.ghaylan.springboot.security.ratelimit.AccessControlManager
import io.ghaylan.springboot.security.utils.EndpointsFinder
import io.ghaylan.springboot.security.utils.getUniqueIdentifier
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
 *   and custom annotation (exactly one must be present).
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
open class SecurityContainer<RoleT, PermissionT, TokenT>(
    private val appContext: ApplicationContext,
    val authExtractors : List<AbstractAuthExtractor>,
    val authDescriptor : AuthDescriptor<*, RoleT, PermissionT, TokenT>,
    val accessControlManager: AccessControlManager,
) where RoleT: Enum<RoleT>, RoleT : RoleAccessPolicy, PermissionT: Enum<PermissionT>, TokenT : Enum<TokenT>, TokenT : TokenAccessPolicy
{
    private val matcher = AntPathMatcher()
    private val logger = LogFactory.getLog(this.javaClass)
    private val _schemas = mutableListOf<SecuritySchema<RoleT, PermissionT, TokenT>>()
    val schemas : List<SecuritySchema<RoleT, PermissionT, TokenT>> get() = _schemas


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
     * - Endpoint must be annotated with exactly **one** of: [PublicEndpoint], [InternalEndpoint], or a custom annotation.
     * - For [InternalEndpoint], an INTERNAL role must exist in [AuthDescriptor].
     * - For [PublicEndpoint], a PUBLIC role must exist in [AuthDescriptor].
     * - For custom annotation:
     *   - Must declare at least one [AuthScheme].
     *   - If using BEARER or API_KEY, roles/permissions must be resolved via [AuthDescriptor].
     *
     * @throws IllegalStateException If annotations are missing, duplicated, or misconfigured.
     */
    private fun getSecuritySpecs(
        method : Method,
        httpMethod : HttpMethod,
        uri : String,
    ) : SecuritySchema<RoleT, PermissionT, TokenT>
    {
        val rateLimit = method.getAnnotation(RateLimited::class.java)

        val internalEndpoint = method.getAnnotation(InternalEndpoint::class.java)
        val publicEndpointAnnotation = method.getAnnotation(PublicEndpoint::class.java)

        val methodSignature = "${method.declaringClass.name}#${method.name} -> $httpMethod $uri"

        if (internalEndpoint != null)
        {
            val roleInternal = authDescriptor.allRoles.find { it.scope == RoleAccessScope.INTERNAL }
            val tokenInternal = authDescriptor.allTokens.find { it.scope == TokenAccessScope.INTERNAL }

            requireNotNull(roleInternal) {
                "Missing INTERNAL role in AuthDescriptor. Endpoint $methodSignature is annotated with @InternalEndpoint but no role with scope=INTERNAL is defined."
            }

            requireNotNull(tokenInternal) {
                "Missing INTERNAL token type in AuthDescriptor. Endpoint $methodSignature is annotated with @InternalEndpoint but no token type with scope=INTERNAL is defined."
            }

            return SecuritySchema(
                id = method.getUniqueIdentifier(),
                method = httpMethod,
                uri = uri,
                authScheme = AuthScheme.BEARER,
                permissions = emptySet(),
                roles = setOf(roleInternal),
                tokenType = tokenInternal,
                accessScope = RoleAccessScope.INTERNAL,
                rateLimit = rateLimit)
        }

        if (publicEndpointAnnotation != null)
        {
            val rolePublic = authDescriptor.allRoles.find { it.scope == RoleAccessScope.PUBLIC }
            val tokenAccess = authDescriptor.allTokens.find { it.scope == TokenAccessScope.ACCESS }

            requireNotNull(rolePublic) {
                "Missing PUBLIC role in AuthDescriptor. Endpoint $methodSignature is annotated with @PublicEndpoint but no role with scope=PUBLIC is defined."
            }

            requireNotNull(tokenAccess) {
                "Missing ACCESS token type in AuthDescriptor. Endpoint $methodSignature is annotated with @PublicEndpoint but no token type with scope=ACCESS is defined."
            }

            return SecuritySchema(
                id = method.getUniqueIdentifier(),
                method = httpMethod,
                uri = uri,
                authScheme = AuthScheme.NONE,
                permissions = emptySet(),
                roles = setOf(rolePublic),
                accessScope = RoleAccessScope.PUBLIC,
                tokenType = tokenAccess,
                rateLimit = rateLimit)
        }

        // Process custom security annotations via the AuthDescriptor
        // This allows applications to define their own security annotations
        val authSpecs = authDescriptor.resolveAuthorizationRequirements(
            method = method,
            pathMatcher = matcher,
            annotations = method.annotations,
            httpMethod = httpMethod,
            uri = uri
        ).copy(rateLimit = rateLimit)

        if (authSpecs.accessScope == RoleAccessScope.PUBLIC) return authSpecs

        require(authSpecs.authScheme != AuthScheme.NONE) {
            "Misconfigured security at $methodSignature. No auth schemes resolved from AuthDescriptor."
        }

        require(authSpecs.tokenType.scope == TokenAccessScope.ACCESS) {
            "Misconfigured security at $methodSignature. Token type must be of scope ACCESS."
        }

        require(authSpecs.roles.isNotEmpty() || authSpecs.permissions.isNotEmpty()) {
            "Misconfigured security at $methodSignature. No roles or permissions resolved from AuthDescriptor."
        }

        return authSpecs
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
    fun findByRequest(request : ServerHttpRequest) : SecuritySchema<*,*,*>?
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
    ) : SecuritySchema<*,*,*>?
    {
        // Try exact match first, then pattern match in one pass
        var fallback: SecuritySchema<*,*,*>? = null

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
     * Finds a security schema by its unique endpoint identifier.
     *
     * @param id The endpoint identifier, typically generated using [Method.getUniqueIdentifier].
     * @return The matching [SecuritySchema] if found, or null if no schema matches the given id.
     */
    fun findByMethodId(id: String) : SecuritySchema<*,*,*>?
    {
        return schemas.find { it.id == id }
    }


    /**
     * Finds a security schema for the given Java/Kotlin method.
     *
     * The method's unique identifier is generated using [Method.getUniqueIdentifier].
     *
     * @param method The method to find the corresponding security schema for.
     * @return The matching [SecuritySchema] if found, or null if no schema matches the method.
     */
    fun findByMethod(method: Method) : SecuritySchema<*,*,*>?
    {
        val id = method.getUniqueIdentifier()
        return schemas.find { it.id == id }
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
            schemes.add(schema.authScheme)

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
            it.authScheme == AuthScheme.HMAC
        }
    }
}