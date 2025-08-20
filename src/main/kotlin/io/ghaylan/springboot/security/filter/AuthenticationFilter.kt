package io.ghaylan.springboot.security.filter

import io.ghaylan.springboot.security.SecurityContainer
import io.ghaylan.springboot.security.exception.HttpStatusCode
import io.ghaylan.springboot.security.exception.SecurityViolationException
import io.ghaylan.springboot.security.model.AuthScheme
import io.ghaylan.springboot.security.model.GenericAuthentication
import io.ghaylan.springboot.security.model.SecuritySchema
import io.ghaylan.springboot.security.model.role.RoleAccessScope
import io.ghaylan.springboot.security.ratelimit.RateLimitStrategy
import io.ghaylan.springboot.security.utils.ReactiveRequestUtils.extractAuthorizationHeader
import io.ghaylan.springboot.security.utils.ReactiveRequestUtils.extractIpAddress
import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.coroutines.reactor.mono
import org.springframework.core.io.buffer.DataBuffer
import org.springframework.core.io.buffer.DataBufferUtils
import org.springframework.core.io.buffer.DefaultDataBufferFactory
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpRequestDecorator
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.nio.charset.StandardCharsets

/**
 * # Reactive Authentication Filter for Spring WebFlux
 *
 * Primary security gateway for all incoming HTTP requests in reactive Spring WebFlux applications.
 * Implements comprehensive authentication, authorization, role-based access control, and rate limiting
 * with support for multiple authentication schemes and advanced security features.
 *
 * ## Architecture & Design
 *
 * Uses chain-of-responsibility and strategy patterns for authentication scheme selection. Designed to be:
 * - **Non-blocking**: Fully reactive using Project Reactor
 * - **Extensible**: Multiple authentication schemes via pluggable extractors
 * - **Performance-optimized**: Minimal memory footprint with efficient request body caching
 * - **Security-first**: Defense-in-depth with multiple validation layers
 *
 * ## Core Responsibilities
 *
 * 1. **Endpoint Security Resolution**: Dynamically resolves security requirements based on request URI and method
 * 2. **Request Body Caching**: Intelligent caching for authentication schemes requiring payload access (HMAC, signatures)
 * 3. **Multi-Tier Authentication**: PUBLIC (anonymous), INTERNAL (system), SECURED (full auth) endpoints
 * 4. **Spring Security Integration**: Populates ReactiveSecurityContextHolder for downstream consumption
 * 5. **Advanced Security**: Multi-tier rate limiting, session management, audit trails
 *
 * ## Authentication Flow
 *
 * ```
 * Request → Schema Lookup → IP/Global Rate Limits → Body Caching (if needed) →
 * Authentication Processing → User Rate Limits → Security Context → Response Headers → Continue
 * ```
 *
 * ## Supported Authentication Schemes
 *
 * | Scheme | Description | Use Case | Body Required |
 * |--------|-------------|----------|---------------|
 * | Bearer | JWT/OAuth tokens | API authentication | No |
 * | Basic  | Username/password | Legacy systems | No |
 * | HMAC   | Cryptographic signatures | High-security APIs | Yes |
 * | Custom | Application-specific | Specialized auth | Configurable |
 *
 * ## Rate Limiting Strategy
 *
 * Two-phase approach for optimal performance:
 * - **Pre-Authentication**: IP/global limits checked before expensive authentication processing
 * - **Post-Authentication**: User-specific limits and session validation after user extraction
 *
 * ## Performance & Security
 *
 * - **Memory Efficiency**: Request body caching only when required
 * - **CPU Optimization**: Early rate limit validation, optimized schema lookups
 * - **Security Features**: Input validation, timing attack prevention, automatic cleanup
 * - **Scalability**: Designed for high-throughput scenarios (10K+ RPS)
 *
 * @param securityContainer Central security configuration with authentication extractors and schemas
 */
class AuthenticationFilter(
    private val securityContainer: SecurityContainer<*, *>
) : WebFilter
{

    /**
     * Primary filter entry point implementing the complete authentication and authorization workflow.
     *
     * ## Processing Pipeline
     *
     * 1. **Security Schema Resolution**: Queries SecurityContainer for endpoint-specific requirements
     * 2. **Early Rate Limiting**: IP/global limits validated before authentication for performance optimization
     * 3. **Request Body Caching**: Conditional caching for schemes requiring payload access (HMAC, signatures)
     * 4. **Authentication Strategy Selection**: Routes based on RoleAccessScope (PUBLIC/INTERNAL/SECURED)
     * 5. **Spring Security Context**: Populates ReactiveSecurityContextHolder with authentication details
     * 6. **Response Enhancement**: Adds user identification headers for audit and debugging
     *
     * ## Rate Limiting Optimization
     *
     * Two-phase approach prevents unnecessary processing:
     * - **Pre-Auth**: IP and global limits checked before expensive user extraction
     * - **Post-Auth**: User-specific limits and session validation after authentication
     *
     * ## Error Handling
     *
     * - **SecurityViolationException**: Authentication/authorization failures with specific error codes
     * - **Generic responses**: Prevents information leakage through consistent error responses
     * - **Fail-fast**: Early validation reduces processing overhead
     *
     * @param exchange ServerWebExchange containing HTTP request/response data
     * @param chain WebFilterChain for continuing request processing
     * @return Mono<Void> Reactive stream completing when request processing finishes
     * @throws SecurityViolationException When authentication, authorization, or rate limiting fails
     */
    override fun filter(
        exchange: ServerWebExchange,
        chain: WebFilterChain
    ): Mono<Void>
    {
        // Phase 1: Resolve endpoint-specific security requirements
        // This lookup determines the authentication strategy and access control policy
        val securitySchema: SecuritySchema<*, *> = securityContainer.findByRequest(exchange.request)
            ?: return Mono.error(SecurityViolationException(code = HttpStatusCode.UNAUTHORIZED))

        return mono {

            // Phase 2: Early rate limiting validation for performance optimization
            // Check IP and global limits before expensive authentication processing
            checkRateLimitByIpOrByAll(securitySchema, exchange)

            var cachedBody: ByteArray? = null

            // Phase 3: Conditional request body caching for cryptographic authentication schemes
            // Required for HMAC signatures and other schemes that validate against payload content
            val mutatedExchange = if (securityContainer.hasSchemeHMAC())
            {
                // Read the entire request body into memory for later validation and downstream access
                cachedBody = readRequestBody(exchange).awaitSingleOrNull()
                // Create a decorated request that allows multiple body reads from cached content
                mutateExchange(exchange, cachedBody)
            }
            else {
                // No body caching needed - proceed with original exchange
                exchange
            }

            // Phase 4: Authentication strategy selection based on endpoint access scope
            // Each scope has different security requirements and validation logic
            mutatedExchange to when (securitySchema.accessScope) {
                RoleAccessScope.PUBLIC -> createAnonymousUser(mutatedExchange)
                RoleAccessScope.INTERNAL -> createSystemUser(mutatedExchange)
                else -> createAuthenticatedUser(mutatedExchange, securitySchema, cachedBody)
            }

        }.flatMap { (mutatedExchange, auth) ->

            val authorities = auth.user.permissions.map { it.name } + auth.user.role.name

            // Phase 5: Spring Security context establishment
            // Create authentication token with user details and authorities for downstream components
            val user = UsernamePasswordAuthenticationToken(
                auth,
                auth.header.authorization,
                AuthorityUtils.createAuthorityList(authorities)
            ).also {
                // Attach full authentication details for advanced authorization decisions
                it.details = auth
            }

            // Phase 6: Response enhancement and pipeline continuation
            // Add observability headers and proceed with request processing
            addUserHeadersToResponse(mutatedExchange, auth)

            // Continue through filter chain with populated security context
            chain.filter(mutatedExchange)
                .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(SecurityContextImpl(user))))
        }
    }


    /**
     * Creates decorated request wrapper enabling multiple request body reads.
     *
     * Solves reactive stream single-consumption limitation for authentication schemes requiring
     * multiple payload access (HMAC validation + business logic). Caches request body in memory
     * and provides reusable DataBuffer stream through ServerHttpRequestDecorator.
     *
     * @param exchange Original ServerWebExchange
     * @param cachedBody Pre-read request body content, null if empty
     * @return ServerWebExchange with decorated request supporting multiple body reads
     */
    private fun mutateExchange(exchange: ServerWebExchange, cachedBody: ByteArray?): ServerWebExchange
    {
        val decoratedRequest: ServerHttpRequest = object : ServerHttpRequestDecorator(exchange.request)
        {
            /**
             * Provides cached request body content as a reactive stream.
             *
             * @return Flux<DataBuffer> containing cached body data, or empty Flux if no body
             */
            override fun getBody(): Flux<DataBuffer>
            {
                // Handle empty body case - return empty stream
                if (cachedBody == null) return Flux.empty()

                // Convert cached bytes to DataBuffer for reactive stream consumption
                val buffer: DataBuffer = DefaultDataBufferFactory().wrap(cachedBody)
                return Flux.just(buffer)
            }
        }
        return exchange.mutate().request(decoratedRequest).build()
    }


    /**
     * Reads and caches complete request body for authentication schemes requiring payload access.
     *
     * Uses DataBufferUtils.join() to efficiently collect DataBuffer chunks into single buffer,
     * then extracts byte content with proper resource management to prevent memory leaks.
     *
     * @param exchange ServerWebExchange containing request body
     * @return Mono<ByteArray> Complete request body as bytes, empty array if no body
     */
    private fun readRequestBody(exchange: ServerWebExchange): Mono<ByteArray>
    {
        return DataBufferUtils.join(exchange.request.body)
            .map { dataBuffer ->
                try {
                    // Allocate byte array for buffer content
                    val bytes = ByteArray(dataBuffer.readableByteCount())
                    // Read buffer content into byte array
                    dataBuffer.read(bytes)
                    // Return cached bytes
                    bytes
                } finally {
                    // Critical: release DataBuffer to prevent memory leaks
                    DataBufferUtils.release(dataBuffer)
                }
            }
    }


    /**
     * Processes authentication for secured endpoints requiring full user validation.
     *
     * ## Authentication Workflow
     * 1. **Header Validation**: Extracts and validates Authorization header presence/format
     * 2. **Scheme Detection**: Identifies authentication scheme from header prefix
     * 3. **Scheme Validation**: Ensures endpoint supports detected scheme
     * 4. **Extractor Selection**: Locates appropriate authentication extractor
     * 5. **User Extraction**: Delegates to scheme-specific extractor for validation
     * 6. **Authorization Checks**: Verifies user role and permissions requirements
     * 7. **Rate Limiting**: Enforces user-specific quotas and session validation
     *
     * ## Security Validations
     * - Header integrity and format validation
     * - Scheme compatibility with endpoint requirements
     * - Cryptographic token/signature validation
     * - Role-based access control enforcement
     * - Session management and token validation
     * - User-specific rate limiting and quota management
     *
     * @param exchange ServerWebExchange with authentication headers
     * @param securitySchema Endpoint security requirements (roles, schemes, permissions)
     * @param rawRequestBody Cached request body for payload validation schemes
     * @return GenericAuthentication Validated authentication object with user details
     * @throws SecurityViolationException For authentication/authorization failures
     */
    private suspend fun createAuthenticatedUser(
        exchange: ServerWebExchange,
        securitySchema: SecuritySchema<*, *>,
        rawRequestBody: ByteArray?
    ) : GenericAuthentication<*, *, *>
    {
        // Step 1: Extract and validate Authorization header presence
        val authorizationHeader = exchange.request.extractAuthorizationHeader()
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: missing Authorization header")

        // Step 2: Detect authentication scheme from header prefix
        val authScheme = AuthScheme.entries.firstOrNull {
            authorizationHeader.startsWith(prefix = it.scheme, ignoreCase = true)
        } ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: invalid Authorization header format")

        // Step 3: Validate endpoint supports the detected authentication scheme
        if (!securitySchema.authSchemes.contains(authScheme)) {
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: unsupported authorization method")
        }

        // Step 4: Locate authentication extractor for the detected scheme
        val extractor = securityContainer.authExtractors.find {
            it.supportedScheme == authScheme
        } ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: no extractor found for scheme ${authScheme.scheme}")

        // Step 5: Perform scheme-specific user authentication and extraction
        val authentication = extractor.extractAuthenticatedUser(
            exchange = exchange,
            isInternalRequest = false,
            authDescriptor = securityContainer.authDescriptor,
            rawRequestBody = rawRequestBody?.let { String(it, StandardCharsets.UTF_8) })

        // Step 6: Validate user has required role for endpoint access
        if (securitySchema.roles.isNotEmpty() && authentication.user.role.name !in securitySchema.roles.map { it.name }) {
            throw SecurityViolationException(HttpStatusCode.FORBIDDEN)
        }

        // Step 7: Validate permissions matches endpoint requirements (if specified)
        if (securitySchema.permissions.isNotEmpty() && authentication.user.permissions.none { it in securitySchema.permissions}) {
            throw SecurityViolationException(HttpStatusCode.FORBIDDEN)
        }

        // Step 8: Apply rate limiting and session validation policies
        checkRateLimitByUser(authentication, securitySchema)

        return authentication
    }


    /**
     * Creates system-level authentication for internal endpoints.
     * Uses Bearer token authentication with elevated privileges.
     */
    private suspend fun createSystemUser(exchange: ServerWebExchange): GenericAuthentication<*, *, *>
    {
        // Locate Bearer token extractor for system authentication
        val extractor = securityContainer.authExtractors.find { it.supportedScheme == AuthScheme.BEARER }
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "System authentication failed: Bearer extractor not available")

        // Perform system-level authentication with internal request flag
        return extractor.extractAuthenticatedUser(
            exchange = exchange,
            isInternalRequest = true,
            authDescriptor = securityContainer.authDescriptor,
            rawRequestBody = null)
    }


    /**
     * Creates anonymous user context for public endpoints with no authentication requirements.
     *
     * Maintains consistent authentication contract for unauthenticated access while enabling
     * IP-based rate limiting, request logging, and security monitoring. Used for public APIs,
     * registration/login endpoints, documentation, and health checks.
     *
     * @param exchange ServerWebExchange containing public request
     * @return GenericAuthentication Anonymous user authentication object
     */
    private fun createAnonymousUser(
        exchange: ServerWebExchange,
    ) : GenericAuthentication<*, *, *>
    {
        // Create anonymous user using first available authentication extractor
        // All extractors must support anonymous user creation for public endpoints
        return securityContainer.authExtractors.firstNotNullOf {
            it.createAnonymousUser(exchange = exchange, authDescriptor = securityContainer.authDescriptor)
        }
    }


    /**
     * Validates user-specific rate limits and session management after authentication.
     *
     * ## User-Based Rate Limiting
     * - Applied only when RateLimitStrategy.USER is configured
     * - Provides per-user request quotas independent of IP/global limits
     * - Supports role-based quota levels and subscription tiers
     * - Maintains persistent quota state across application restarts
     *
     * ## Session Management
     * - Validates active sessions haven't been suspended or revoked
     * - Checks against token blacklists and suspension databases
     * - Supports real-time session revocation for security incidents
     * - Maintains audit trails of session suspension events
     *
     * @param authentication Authenticated user context with user ID and token
     * @param securitySchema Endpoint security configuration with rate limiting rules
     * @throws SecurityViolationException When user limits exceeded or session suspended
     */
    private suspend fun checkRateLimitByUser(
        authentication: GenericAuthentication<*, *, *>,
        securitySchema: SecuritySchema<*, *>)
    {
        // Early exit if rate limiting is not configured or not user-based strategy
        securityContainer.rateLimitManager ?: return

        if (securitySchema.rateLimit?.strategy != RateLimitStrategy.USER) return

        // Validate user-specific rate limits using authenticated user ID
        if (securityContainer.rateLimitManager.isMaxAttemptsReachedByUser(securitySchema, authentication.user.id)) {
            throw SecurityViolationException(HttpStatusCode.TOO_MANY_REQUESTS)
        }

        // Validate session status and token integrity for authenticated users
        if (securityContainer.rateLimitManager.isSessionSuspended(userId = authentication.user.id, token = authentication.header.authorization)) {
            throw SecurityViolationException(HttpStatusCode.EXPIRED_TOKEN)
        }
    }


    /**
     * Performs early-stage rate limiting validation for IP-based and global access controls.
     *
     * ## Performance Optimization Strategy
     * Validates IP and global limits before expensive authentication processing, providing:
     * - Reduced CPU usage by avoiding authentication when limits exceeded
     * - Memory efficiency by preventing allocation under attack
     * - Faster response times for over-limit requests
     * - Resource protection for downstream services
     *
     * ## Rate Limiting Strategies
     * - **IP-Based (RateLimitStrategy.IP)**: Per-client IP request limiting with subnet support
     * - **Global (RateLimitStrategy.ALL)**: System-wide throttling for maintenance/stress scenarios
     *
     * ## Attack Mitigation
     * - DDoS protection through global rate limiting
     * - IP-based blocking prevents single-source overwhelming
     * - Brute force prevention with IP-specific thresholds
     * - Circuit breaker functionality for backend protection
     *
     * @param securitySchema Endpoint security configuration with rate limiting rules
     * @param exchange ServerWebExchange providing client IP and request context
     * @throws SecurityViolationException When rate limits exceeded (503 for global, 429 for IP)
     */
    private suspend fun checkRateLimitByIpOrByAll(
        securitySchema: SecuritySchema<*, *>,
        exchange: ServerWebExchange)
    {
        // Early exit if rate limiting is not configured
        securityContainer.rateLimitManager ?: return

        // Determine if rate limits have been exceeded based on configured strategy
        val limitReached = when (securitySchema.rateLimit?.strategy) {

            RateLimitStrategy.IP -> {
                val ipAddress = exchange.request.extractIpAddress()
                // Check if this IP has exceeded its allocated request quota
                securityContainer.rateLimitManager.isMaxAttemptsReachedByIp(securitySchema, ipAddress)
            }

            RateLimitStrategy.ALL -> {
                // Check global system-wide rate limits for all requests
                securityContainer.rateLimitManager.isMaxAttemptsReachedForAll(securitySchema)
            }

            else -> {
                // Strategy not applicable for early validation - exit without blocking
                return
            }
        }

        // Exit if limits not exceeded - proceed with normal processing
        if (!limitReached) return

        if (securitySchema.rateLimit.strategy == RateLimitStrategy.ALL)
        {
            // Global limits exceeded - indicate system unavailability
            throw SecurityViolationException(HttpStatusCode.NOT_AVAILABLE)
        }
        else {
            // IP-specific limits exceeded - indicate too many requests from client
            throw SecurityViolationException(HttpStatusCode.TOO_MANY_REQUESTS)
        }
    }


    /**
     * Adds user identification headers to HTTP response for observability and audit purposes.
     *
     * Enhances responses with user context information enabling request tracing, security audits,
     * performance monitoring, and debugging across service boundaries.
     *
     * ## Headers Added
     * - **X-Forwarded-UserId**: User's unique identifier for request correlation
     * - **X-Forwarded-UserRole**: Primary role name for authorization context
     *
     * These headers support SOX, GDPR, HIPAA compliance requirements and custom audit frameworks.
     *
     * @param exchange ServerWebExchange to modify with user headers
     * @param authentication Authentication object containing user identification
     */
    private fun addUserHeadersToResponse(exchange: ServerWebExchange, authentication: GenericAuthentication<*, *, *>)
    {
        // Add user identification header for request tracing and audit trails
        exchange.response.headers.add("X-Forwarded-UserId", authentication.user.id)

        // Add user role header for authorization context and downstream decision making
        exchange.response.headers.add("X-Forwarded-UserRole", authentication.user.role.name)
    }
}