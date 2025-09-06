package io.ghaylan.springboot.security.exception

import org.springframework.http.HttpStatus

/**
 * Exception representing a security violation in the application.
 *
 * This exception is used throughout the reactive security layer to signal authentication
 * or authorization failures, token issues, or rate limiting. Instead of manually writing
 * HTTP responses, throwing this exception allows a centralized global exception handler
 * to generate consistent JSON error responses for the API.
 *
 * Example usage in a WebFlux security filter:
 * ```kotlin
 * if (userNotAuthenticated) {
 *     return Mono.error(SecurityViolationException(HttpStatusCode.UNAUTHORIZED))
 * }
 * ```
 *
 * @property code The [HttpStatusCode] representing the type of security violation and its associated HTTP status.
 * @param message Optional detailed error message; defaults to the message defined in [code].
 */
class SecurityViolationException(
    val code : HttpStatusCode,
    message : String = code.message,
) : RuntimeException(message)


/**
 * Enum representing common HTTP status codes and messages for security-related exceptions.
 *
 * Each entry defines:
 * - [status]: The corresponding [HttpStatus] to return in the response.
 * - [message]: A descriptive error message explaining the reason for the security violation.
 *
 * Designed to be used with [SecurityViolationException] for centralized, consistent error handling.
 */
enum class HttpStatusCode(val status : HttpStatus, val message : String)
{
    INVALID_TOKEN(status = HttpStatus.FORBIDDEN, "Access denied: Token type not allowed here."),

    /** Access denied due to insufficient roles or permissions. Returns HTTP 403 Forbidden. */
    FORBIDDEN(status = HttpStatus.FORBIDDEN, "Access denied: You do not have the required role to access this endpoint."),

    /** Authentication failure due to missing or invalid credentials. Returns HTTP 401 Unauthorized. */
    UNAUTHORIZED(status = HttpStatus.UNAUTHORIZED, "Authentication failed: invalid or missing credentials."),

    /** Authentication failure due to expired session or token. Returns HTTP 401 Unauthorized. */
    EXPIRED_TOKEN(status = HttpStatus.UNAUTHORIZED, "Authentication failed: Your session has expired. Please log in again."),

    /** Service is temporarily unavailable. Returns HTTP 503 Service Unavailable. */
    SERVICE_UNAVAILABLE(status = HttpStatus.SERVICE_UNAVAILABLE, "Service temporarily unavailable: Please try again later."),

    /** Too many requests have been made. Returns HTTP 429 Too Many Requests. */
    TOO_MANY_REQUESTS(status = HttpStatus.TOO_MANY_REQUESTS, "Too many requests: You have exceeded the allowed number of attempts. Please wait and try again.")
}