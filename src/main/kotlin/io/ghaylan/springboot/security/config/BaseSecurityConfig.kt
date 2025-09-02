package io.ghaylan.springboot.security.config

import io.ghaylan.springboot.security.AuthDescriptor
import io.ghaylan.springboot.security.SecurityContainer
import io.ghaylan.springboot.security.extractor.ApiKeyAuthExtractor
import io.ghaylan.springboot.security.extractor.BasicAuthExtractor
import io.ghaylan.springboot.security.extractor.BearerAuthExtractor
import io.ghaylan.springboot.security.extractor.HmacAuthExtractor
import io.ghaylan.springboot.security.filter.AccessDeniedHandler
import io.ghaylan.springboot.security.filter.AuthenticationEntryPoint
import io.ghaylan.springboot.security.filter.AuthenticationFilter
import io.ghaylan.springboot.security.model.AuthScheme
import io.ghaylan.springboot.security.ratelimit.AccessControlManager
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository
import java.util.Optional
import kotlin.jvm.optionals.getOrNull

/**
 * Base Spring Security configuration for JWT-based reactive authentication and authorization.
 *
 * This auto-configuration establishes a comprehensive security foundation for Spring WebFlux applications
 * with stateless authentication, dynamic role-based access control, and multiple authentication schemes.
 *
 * ## Key Features
 * - **Stateless JWT Authentication**: No server-side sessions, CORS/CSRF disabled for API design
 * - **Dynamic Authorization**: Security schemas applied based on endpoint configurations
 * - **Multi-Scheme Support**: Bearer tokens, API keys, HMAC signatures, and Basic authentication
 * - **Rate Limiting Integration**: Optional request throttling and abuse prevention
 * - **Standardized Error Handling**: Consistent JSON error responses for security violations
 *
 * ## Architecture
 * The configuration assembles security components into a cohesive pipeline:
 * 1. **Authentication Extractors**: Handle different authentication schemes
 * 2. **Security Container**: Manages schemas and coordinates authentication flow
 * 3. **Custom Filter**: Processes requests through authentication pipeline
 * 4. **Error Handlers**: Provide consistent error responses for security failures
 *
 * ## Security Model
 * - **Stateless Design**: Each request carries authentication credentials
 * - **Schema-Based Authorization**: Permissions defined per endpoint
 * - **Flexible Authentication**: Multiple schemes supported simultaneously
 * - **Performance Optimized**: Early rate limiting and efficient schema lookups
 */
@AutoConfiguration
@EnableWebFluxSecurity
open class BaseSecurityConfig
{

    /**
     * Creates access denied handler for authorization failures.
     *
     * Handles requests where authenticated users lack sufficient permissions,
     * returning standardized JSON error responses with HTTP 403 status.
     */
    @Bean
    open fun accessDeniedHandler(): AccessDeniedHandler = AccessDeniedHandler()


    /**
     * Creates authentication entry point for unauthenticated requests.
     *
     * Handles requests lacking valid authentication credentials,
     * returning standardized JSON error responses with HTTP 401 status.
     */
    @Bean
    open fun authenticationEntryPoint(): AuthenticationEntryPoint = AuthenticationEntryPoint()


    /**
     * Creates the central security container managing authentication and authorization.
     *
     * The container coordinates authentication extractors, authorization descriptors, and rate limiting
     * to provide unified security processing. Requires at least one authentication extractor to function.
     *
     * ## Authentication Extractors
     * - **ApiKeyAuthExtractor**: API key-based authentication for service clients
     * - **BasicAuthExtractor**: HTTP Basic authentication for legacy compatibility
     * - **BearerAuthExtractor**: JWT/OAuth Bearer token authentication
     * - **HmacAuthExtractor**: HMAC signature-based authentication for high security
     *
     * ## Optional Components
     * - **RateLimitManager**: Request throttling and abuse prevention
     * - **Dynamic Assembly**: Only available extractors are included in container
     *
     * @param appContext Spring application context for bean discovery
     * @param authDescriptor Project-specific authentication mapping and validation logic
     * @param apiKeyAuthExtractor Optional API key authentication handler
     * @param basicAuthExtractor Optional Basic authentication handler
     * @param bearerAuthExtractor Optional Bearer token authentication handler
     * @param hmacAuthExtractor Optional HMAC signature authentication handler
     * @param accessControlManager Optional rate limiting and throttling manager
     * @return Configured SecurityContainer with available authentication methods
     * @throws IllegalArgumentException if no authentication extractors are available
     */
    @Bean
    open fun securityContainer(
        appContext: ApplicationContext,
        authDescriptor: AuthDescriptor<*,*,*,*>,
        apiKeyAuthExtractor : Optional<ApiKeyAuthExtractor>,
        basicAuthExtractor : Optional<BasicAuthExtractor>,
        bearerAuthExtractor : Optional<BearerAuthExtractor>,
        hmacAuthExtractor : Optional<HmacAuthExtractor>,
        accessControlManager: AccessControlManager
    ) : SecurityContainer<*,*,*>
    {
        val authExtractors = listOfNotNull(
            apiKeyAuthExtractor.getOrNull(),
            basicAuthExtractor.getOrNull(),
            bearerAuthExtractor.getOrNull(),
            hmacAuthExtractor.getOrNull())

        require(authExtractors.isNotEmpty()) {
            "SecurityContainer requires at least one authentication extractor to operate correctly."
        }

        return SecurityContainer(
            appContext = appContext,
            authDescriptor = authDescriptor,
            authExtractors = authExtractors,
            accessControlManager = accessControlManager)
    }


    @Bean
    open fun accessControlManager(redisTemplate: ReactiveStringRedisTemplate) = AccessControlManager(redisTemplate)

    /**
     * Creates the main authentication filter for request processing.
     *
     * This filter handles the complete authentication workflow including token validation,
     * security schema enforcement, rate limiting, and access control for all requests.
     *
     * @param securityContainer Security container with authentication configuration
     * @return Configured AuthenticationFilter for request processing
     */
    @Bean
    open fun authenticationFilter(
        securityContainer: SecurityContainer<*,*,*>
    ) : AuthenticationFilter = AuthenticationFilter(securityContainer)


    /**
     * Configures the Spring Security filter chain with comprehensive security policies.
     *
     * Establishes a stateless, API-focused security configuration with dynamic authorization
     * based on endpoint security schemas and integrated custom authentication processing.
     *
     * ## Security Policies
     * - **Stateless Architecture**: No server-side sessions, optimized for scalability
     * - **API-First Design**: CORS/CSRF disabled, HTTP Basic/Form login disabled
     * - **Dynamic Authorization**: Role requirements applied per endpoint schema
     * - **Custom Authentication**: Integrated AuthenticationFilter for multi-scheme support
     * - **Standardized Errors**: Consistent JSON responses for authentication/authorization failures
     *
     * ## Authorization Strategy
     * - **Schema-Based**: Permissions defined by endpoint security schemas
     * - **Role-Based**: User roles matched against required endpoint roles
     * - **Deny-by-Default**: Unmatched requests rejected automatically
     * - **Dynamic Mapping**: URI patterns and HTTP methods from security container
     *
     * ## Filter Integration
     * The custom AuthenticationFilter is positioned before Spring Security's built-in authentication
     * filter to handle multi-scheme authentication and populate the security context appropriately.
     *
     * @param http ServerHttpSecurity builder for configuring reactive security
     * @param authFilter Custom authentication filter for multi-scheme processing
     * @param entryPoint Authentication entry point for unauthenticated access
     * @param accessDeniedHandler Access denied handler for insufficient permissions
     * @param securityContainer Security container with endpoint schemas and configuration
     * @return Configured SecurityWebFilterChain with complete security policies
     */
    @Bean
    open fun securityWebFilterChain(
        http: ServerHttpSecurity,
        authFilter: AuthenticationFilter,
        entryPoint: AuthenticationEntryPoint,
        accessDeniedHandler: AccessDeniedHandler,
        securityContainer: SecurityContainer<*,*,*>
    ) : SecurityWebFilterChain
    {
        return http
            // Configure stateless API security
            .cors { it.disable() }
            .csrf { it.disable() }
            .httpBasic { it.disable() }
            .formLogin { it.disable() }

            // Configure stateless session management
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())

            // Apply dynamic authorization based on security schemas
            .authorizeExchange { exchanges ->
                securityContainer.schemas.forEach { schema ->
                    val requiredRoles = (schema.roles.map { it.name } + schema.permissions.map { it.name }).toTypedArray()
                    exchanges.pathMatchers(schema.method, schema.uri).hasAnyAuthority(*requiredRoles)
                }

                // Deny all unmatched requests by default
                exchanges.anyExchange().denyAll()
            }

            // Configure custom error handling
            .exceptionHandling { handling ->
                handling.authenticationEntryPoint(entryPoint)
                handling.accessDeniedHandler(accessDeniedHandler)
            }

            // Add custom reactive authentication filter
            .addFilterBefore(authFilter, SecurityWebFiltersOrder.AUTHENTICATION)

            .build()
    }
}