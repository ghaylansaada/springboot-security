package io.ghaylan.springboot.security.utils.jwt

import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.Jwts
import java.security.PublicKey

/**
 * Utility object for handling JWT (JSON Web Token) operations.
 *
 * Provides helper constants and methods for parsing and verifying JWT tokens
 * in a secure and standardized way.
 *
 * ## Features
 * - **RSA Public Key Verification**: Supports JWT signature verification using RSA public keys.
 * - **Standard Claim Keys**: Predefined keys for common JWT claims, improving consistency across the application.
 * - **Clock Skew Handling**: Accounts for small differences between server and client clocks.
 *
 * ## Predefined JWT Claim Keys
 * - [KEY_USER_ID] (`"uid"`): Unique identifier of the user.
 * - [KEY_USER_ROLE] (`"urole"`): User role or permissions.
 * - [KEY_USER_NAME] (`"uname"`): User display name.
 *
 * ## Security Considerations
 * - Always verify JWT signatures with a trusted public key.
 * - Validate claims such as `audience`, `expiration`, and `issuer` after parsing.
 * - Handle clock skew appropriately to avoid token rejection due to small time differences.
 */
object JwtUtils
{
    /** Algorithm used for key generation/verification (RSA) */
    const val KEY_FACTORY_ALGORITHM: String = "RSA"

    /** Claim key for user ID */
    const val KEY_USER_ID: String = "uid"

    /** Claim key for user role */
    const val KEY_USER_ROLE: String = "urole"

    /** Claim key for user role */
    const val KEY_USER_PERMISSIONS: String = "uper"

    /** Claim key for user display name */
    const val KEY_USER_NAME: String = "uname"


    /**
     * Creates a JWT parser configured with the provided public key for signature verification.
     *
     * The parser uses a clock skew tolerance of 30 seconds to account for small differences
     * between system clocks.
     *
     * Example:
     * ```kotlin
     * val parser = JwtUtils.getParser(publicKey)
     * val claims = parser.parseClaimsJws(jwtToken).body
     * val userId = claims[JwtUtils.KEY_USER_ID]
     * ```
     *
     * @param publicKey RSA public key used to verify the JWT signature.
     * @return Configured [JwtParser] instance for parsing and verifying JWT tokens.
     */
	fun getParser(publicKey : PublicKey) : JwtParser
	{
		return Jwts.parser()
			.verifyWith(publicKey)
			.clockSkewSeconds(30)
			.build()
	}
}