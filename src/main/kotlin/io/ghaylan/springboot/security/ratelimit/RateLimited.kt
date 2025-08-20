package io.ghaylan.springboot.security.ratelimit

import java.time.temporal.ChronoUnit

/**
 * Annotation for rate-limiting access to controller methods in Spring applications.
 *
 * This annotation allows restricting the number of requests to a specific endpoint
 * within a configurable time window. It supports multiple strategies for grouping
 * requests, such as per-user, per-IP, or globally.
 *
 * Use this annotation to prevent abuse, ensure fair resource usage, and protect
 * APIs from excessive or malicious traffic.
 *
 * ### Usage Example
 * ```kotlin
 * @RateLimited(
 *     maxAttempts = 5,
 *     duration = 1,
 *     timeUnit = ChronoUnit.MINUTES,
 *     strategy = RateLimitStrategy.USER)
 * @GetMapping("/api/resource")
 * suspend fun getResource(): String = "Resource accessed"
 * ```
 *
 * This example limits access to **5 requests per minute per authenticated user**.
 *
 * ---
 *
 * ### Notes
 * - Use [RateLimitStrategy.IP] to restrict requests based on client IP addresses.
 * - Use [RateLimitStrategy.USER] to limit requests per authenticated user. Requires authentication context.
 * - Use [RateLimitStrategy.ALL] to enforce a global limit across all clients and users.
 * - Applying this annotation at the method level only affects the annotated endpoint.
 *   Consider combining with controller-level configuration for consistent global policies.
 *
 * ### Parameters
 * @property maxAttempts Maximum number of requests allowed within the specified time window.
 * @property duration Length of the time window for request counting.
 * @property timeUnit Unit of time for the [duration] (e.g., [ChronoUnit.SECONDS], [ChronoUnit.MINUTES]).
 * @property strategy Strategy to determine how requests are grouped for rate limiting. Defaults to [RateLimitStrategy.USER].
 */
@MustBeDocumented
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION)
annotation class RateLimited(
    val maxAttempts: Int,
    val duration: Long,
    val timeUnit: ChronoUnit,
    val strategy: RateLimitStrategy = RateLimitStrategy.USER)

/**
 * Strategies for grouping requests in rate limiting.
 *
 * Defines how request counts are applied, whether per user, per IP address, or globally.
 */
enum class RateLimitStrategy
{
    /** Apply rate limiting per client IP address. */
    IP,

    /** Apply rate limiting per authenticated user. */
    USER,

    /** Apply rate limiting globally across all requests. */
    ALL
}
