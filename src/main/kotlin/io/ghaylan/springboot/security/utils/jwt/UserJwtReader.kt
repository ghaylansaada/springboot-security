package io.ghaylan.springboot.security.utils.jwt

import io.ghaylan.springboot.security.extractor.RawExtractedAuth
import io.ghaylan.springboot.security.model.role.RoleAccessPolicy
import io.jsonwebtoken.Claims
import java.security.PublicKey

/**
 * Utility for **parsing and validating user JWT tokens**.
 *
 * This class is designed to extract user authentication information from JWTs
 * issued for users. It validates the JWT signature using a public key and exposes
 * convenient methods to retrieve claims and map them to [RawExtractedAuth].
 *
 * ## Security Features
 * - **JWT Parsing**: Validates JWTs using a public key; no private key needed.
 * - **Claims Extraction**: Extracts standard claims like user ID, role, name, and permissions.
 * - **Audience Validation**: Supports reading and validating audience claims.
 * - **Custom Claims**: Provides access to application-specific claims stored under `claims`.
 * - **Generic Role/Permissions Support**: Compatible with enums implementing [RoleAccessPolicy].
 *
 * ## Token Structure
 * User JWT tokens should include:
 * - **User ID** (`uid`) – unique identifier for the user.
 * - **User Role** (`urole`) – the role of the user.
 * - **User Name** (`uname`) – display name or username.
 * - **User Permissions** (uper) – identifies the permissions of the user.
 * - **Custom Claims** (`claims`) – optional application-specific payload.
 *
 * ## Usage Example
 * ```kotlin
 * @Bean
 * fun userJwtReader(publicKey: PublicKey): UserJwtReader {
 *     return UserJwtReader(publicKey)
 * }
 *
 * // Resolving a JWT from an authorization header
 * val userAuth = userJwtReader.resolve("Bearer eyJhbGciOiJIUzI1NiIs...")
 *
 * // Accessing specific claims
 * val claims = userJwtReader.getClaims("Bearer eyJhbGciOiJIUzI1NiIs...")
 * val audience = userJwtReader.getAudience(claims)
 * val customValue = userJwtReader.getClaim("custom_key", claims)
 * ```
 *
 * ## Integration
 * The extracted [RawExtractedAuth] can be mapped to your project-specific
 * authentication type via [AuthDescriptor.mapGenericAuth()] in your authentication flow.
 *
 * ## Error Handling
 * Returns `null` for invalid tokens. Common validation failures include:
 * - Invalid signature
 * - Expired token
 * - Malformed JWT structure
 * - Missing required claims
 *
 * @param publicKey The public key used to verify JWT signatures.
 */
class UserJwtReader(publicKey : PublicKey)
{
    /** JWT parser configured with the provided public key. */
	private val jwtParser = JwtUtils.getParser(publicKey)


    /**
     * Converts JWT claims into a [RawExtractedAuth] object.
     *
     * This method extracts required fields (user ID, role, name, token type) and
     * automatically adds all other claims to the [RawExtractedAuth] map, making
     * them accessible as dynamic properties.
     *
     * @param claims The JWT claims extracted from a token.
     * @return A [RawExtractedAuth] containing user info and additional claims,
     *         or `null` if any required claim (id, role, tokenType) is missing.
     */
    fun resolve(claims : Claims) : RawExtractedAuth?
	{
        val result = RawExtractedAuth(
			id = claims[JwtUtils.KEY_USER_ID]?.toString() ?: return null,
			role = claims[JwtUtils.KEY_USER_ROLE]?.toString() ?: return null,
			name = claims[JwtUtils.KEY_USER_NAME]?.toString(),
			permissions = getStringListFromClaim(claims, JwtUtils.KEY_USER_PERMISSIONS),
			credentials = null)

        for (entry in claims.entries) {

            if (entry.key == JwtUtils.KEY_USER_ID) continue
            if (entry.key == JwtUtils.KEY_USER_ROLE) continue
            if (entry.key == JwtUtils.KEY_USER_NAME) continue

            result[entry.key] = entry.value
        }

        return result
	}


    /**
     * Safely retrieves a claim from [claims] as a list of strings.
     *
     * JWT claims are stored as [Any], so this function handles multiple cases:
     * - If the claim is a [List<*>] or [Array<*>], it filters only string elements.
     * - If the claim is a single [String], it wraps it into a list.
     * - If the claim is missing or of an unexpected type, returns an empty list.
     *
     * @param claims The JWT claims map.
     * @param key The claim key to retrieve.
     * @return A [List<String>] containing the claim values, or an empty list if not present.
     */
    fun getStringListFromClaim(claims: Claims, key: String): List<String>
    {
        val raw = claims[key] ?: return emptyList()

        return when (raw)
        {
            is List<*> -> raw.filterIsInstance<String>()
            is Array<*> -> raw.filterIsInstance<String>()
            is String -> listOf(raw)
            else -> emptyList()
        }
    }


    /**
     * Resolves a JWT from an authorization string.
     *
     * @param authorization The JWT string, usually from an HTTP Authorization header.
     * @return A [RawExtractedAuth] object or `null` if the token is invalid.
     */
	fun resolve(authorization : String) : RawExtractedAuth?
	{
		val claims = getClaims(authorization) ?: return null

		return resolve(claims)
	}


    /**
     * Retrieves the audience claim from the provided JWT claims.
     *
     * @param claims JWT claims.
     * @return A set of audience strings, or `null` if not present.
     */
	fun getAudience(claims: Claims) : Set<String>?
	{
		return claims.audience
	}


    /**
     * Retrieves a custom claim from the JWT claims.
     *
     * @param key The key of the claim.
     * @param claims The JWT claims.
     * @return The claim value, or `null` if not present.
     */
	fun getClaim(key : String, claims: Claims) : Any?
	{
		return claims[key]
	}


    /**
     * Parses a JWT string and returns its claims payload.
     *
     * @param authorization The JWT string.
     * @return JWT claims, or `null` if the token is invalid.
     */
	fun getClaims(
		authorization : String,
	) : Claims?
	{
		return jwtParser.parseSignedClaims(authorization)?.payload
	}
}