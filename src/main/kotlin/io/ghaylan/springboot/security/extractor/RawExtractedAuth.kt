package io.ghaylan.springboot.security.extractor

/**
 * Raw authentication data extracted from HTTP requests.
 *
 * This data class represents the unprocessed authentication information extracted
 * from HTTP requests by authentication extractors. It contains the basic user identity
 * and authentication details **before they are mapped or converted to the standardized
 * authentication format** used in your application.
 *
 * Extending [HashMap] allows storing **additional dynamic key-value pairs** alongside
 * the core authentication fields, making it flexible for custom claims or extra data
 * extracted from tokens or headers.
 *
 * ## Usage
 * - Used internally by authentication extractors to pass raw authentication data
 *   to security components for validation or mapping.
 * - Supports adding custom properties dynamically via the `put` method inherited
 *   from [HashMap].
 *
 * ```kotlin
 * val rawAuth = RawExtractedAuth(
 *     id = "user123",
 *     role = "ADMIN",
 *     name = "John Doe",
 *     permissions = listOf("READ", "WRITE"),
 *     credentials = "raw-token-or-password")
 *
 * rawAuth["customClaim"] = "some value"
 * ```
 *
 * ## Notes
 * - The core fields (`id`, `role`, `name`, `permissions`, `credentials`) represent
 *   standard authentication information.
 * - `HashMap` extension allows storing any additional attributes needed during
 *   authentication flow, such as claims or metadata.
 *
 * @param id The unique user identifier.
 * @param role The user's role as a string (will later be converted to enum if needed).
 * @param name The user's display name, if available.
 * @param permissions The user's permissions as List of strings (will later be mapped to enums if needed).
 * @param credentials The raw credentials used for authentication, such as a password or token string.
 */
data class RawExtractedAuth(
    val id: String,
    val role: String,
    val name: String?,
    val tokenType: String?,
    val permissions: List<String>?,
    val credentials: String?,
) : HashMap<String, Any?>()