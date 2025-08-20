package io.ghaylan.springboot.security.annotations

/**
 * Designates an endpoint as publicly accessible, bypassing all authentication and authorization checks.
 *
 * Use this annotation to explicitly mark controller methods that should be accessible by unauthenticated clients.
 * When applied, the annotated endpoint is excluded from the security filter chain, allowing unrestricted access.
 *
 * ## ⚠️ Security Considerations
 * Although authentication is bypassed, the following precautions are highly recommended:
 *
 * - **Rate Limiting**: Implement rate limiting to prevent abuse or denial-of-service attacks.
 * - **Data Exposure**: Ensure only non-sensitive, intentionally public data is exposed.
 *
 * ## ✅ Recommended Use Cases
 * - Publicly available data (e.g., open APIs, status endpoints)
 * - User authentication and registration flows
 * - Static content or public documentation
 *
 * ## ❌ Misuse Warning
 * Do **not** use this annotation on endpoints that expose sensitive operations or data.
 * Misuse can lead to severe security vulnerabilities, including unauthorized data access or service misuse.
 *
 * ## Example Usage
 * ```kotlin
 * @PublicEndpoint
 * @PostMapping("/api/auth/login")
 * suspend fun login(@RequestBody credentials: LoginRequest): ResponseEntity<AuthResponse> {
 *     // This endpoint is publicly accessible
 * }
 * ```
 */
@MustBeDocumented
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class PublicEndpoint