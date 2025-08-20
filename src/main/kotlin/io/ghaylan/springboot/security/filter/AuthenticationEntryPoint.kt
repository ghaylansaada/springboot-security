package io.ghaylan.springboot.security.filter

import io.ghaylan.springboot.security.exception.HttpStatusCode
import io.ghaylan.springboot.security.exception.SecurityViolationException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Reactive authentication entry point for Spring WebFlux security.
 *
 * This class is invoked whenever an unauthenticated user attempts to access a protected resource.
 * Instead of manually writing the HTTP response, it throws a [SecurityViolationException] with
 * an appropriate HTTP status, which can then be handled by a global exception handler to produce
 * a consistent API error response structure.
 *
 * Example usage:
 * ```kotlin
 * @Bean
 * fun securityWebFilterChain(http: ServerHttpSecurity, entryPoint: AuthenticationEntryPoint): SecurityWebFilterChain {
 *     return http
 *         .exceptionHandling { it.authenticationEntryPoint(entryPoint) }
 *         .build()
 * }
 * ```
 *
 * Behavior:
 * - Triggered when authentication is required but missing or invalid.
 * - Returns a reactive [Mono] that emits a [SecurityViolationException] with HTTP 401 Unauthorized.
 *
 * Advantages:
 * - Centralizes error handling through a global exception handler.
 * - Supports stateless, JSON-based APIs without manually writing the response.
 *
 * @constructor Creates a new instance of [AuthenticationEntryPoint].
 */
class AuthenticationEntryPoint : ServerAuthenticationEntryPoint
{

    /**
     * Handles authentication failures for reactive WebFlux endpoints.
     *
     * @param exchange The current [ServerWebExchange] representing the HTTP request/response.
     * @param exception The [AuthenticationException] that caused the authentication failure.
     * @return A [Mono] that emits a [SecurityViolationException] with HTTP status 401.
     */
    override fun commence(
        exchange: ServerWebExchange,
        exception: AuthenticationException
    ) : Mono<Void>
    {
        return Mono.error {
            SecurityViolationException(code = HttpStatusCode.UNAUTHORIZED)
        }
    }
}