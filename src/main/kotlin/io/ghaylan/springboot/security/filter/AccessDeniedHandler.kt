package io.ghaylan.springboot.security.filter

import io.ghaylan.springboot.security.exception.HttpStatusCode
import io.ghaylan.springboot.security.exception.SecurityViolationException
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Reactive access denied handler for Spring WebFlux security.
 *
 * This class is invoked whenever an **authenticated user** attempts to access a resource
 * they do not have permission for. Instead of manually writing the HTTP response,
 * it throws a [SecurityViolationException] with an appropriate HTTP status,
 * which can then be handled by a global exception handler to produce a consistent API error response.
 *
 * Example usage:
 * ```kotlin
 * @Bean
 * fun securityWebFilterChain(http: ServerHttpSecurity, accessDeniedHandler: AccessDeniedHandler): SecurityWebFilterChain {
 *     return http
 *         .exceptionHandling { it.accessDeniedHandler(accessDeniedHandler) }
 *         .build()
 * }
 * ```
 *
 * Behavior:
 * - Triggered when the user is authenticated but lacks the required authorities or roles.
 * - Returns a reactive [Mono] that emits a [SecurityViolationException] with HTTP 403 Forbidden.
 *
 * Advantages:
 * - Centralizes error handling through a global exception handler.
 * - Supports stateless, JSON-based APIs without manually writing the response.
 *
 * @constructor Creates a new instance of [AccessDeniedHandler].
 */
class AccessDeniedHandler : ServerAccessDeniedHandler
{

    /**
     * Handles authorization failures for reactive WebFlux endpoints.
     *
     * @param exchange The current [ServerWebExchange] representing the HTTP request/response.
     * @param denied The [AccessDeniedException] that caused the access denial.
     * @return A [Mono] that emits a [SecurityViolationException] with HTTP status 403.
     */
    override fun handle(
        exchange: ServerWebExchange,
        denied: AccessDeniedException)
    : Mono<Void>
    {
        return Mono.error {
            SecurityViolationException(code = HttpStatusCode.FORBIDDEN)
        }
    }
}