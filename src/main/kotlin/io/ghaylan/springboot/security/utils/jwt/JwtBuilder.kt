package io.ghaylan.springboot.security.utils.jwt

import io.ghaylan.springboot.security.model.role.RoleAccessPolicy
import io.ghaylan.springboot.security.model.token.TokenAccessPolicy
import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.Jwts
import java.security.PrivateKey
import java.time.*
import java.util.*

/**
 * A fluent builder for creating JSON Web Tokens (JWTs) with customizable claims, payload encoding,
 * compression, and RS256 signing.
 *
 * This class wraps the JJWT [JwtBuilder] to provide a consistent and type-safe API for building
 * JWTs that conform to the application's security model. It supports standard JWT claims such as
 * expiration, subject, issuer, and audience, as well as custom claims.
 *
 * ## Usage Example
 * ```kotlin
 * val token = JwtBuilder.builder(userId, userRole, tokenType)
 *     .setExpiration(Instant.now().plusSeconds(120))
 *     .setIssuer("my-service")
 *     .addAudience("target-service::POST::/api/data")
 *     .setClaim("custom", "value")
 *     .compress()
 *     .build(privateKey)
 * ```
 *
 * @property builder The underlying JJWT [JwtBuilder] used for JWT construction.
 */
class JwtBuilder private constructor(private val builder : JwtBuilder)
{
	companion object
	{
        /**
         * Initializes a [JwtBuilder] with standard claims for a specific user.
         *
         * This method sets up a JWT with all required claims for authentication and authorization:
         * - `userId` – the unique identifier of the user
         * - `userRole` – the primary role of the user, enforcing type safety via [RoleAccessPolicy]
         * - `userPermissions` – a list of fine-grained permissions granted to the user
         * - `iat` (issued-at) – automatically set to the current timestamp
         *
         * The returned [JwtBuilder] can be further customized with standard JWT fields such as:
         * - `iss` (issuer)
         * - `aud` (audience)
         * - `exp` (expiration)
         *
         * ## Usage Example
         * ```kotlin
         * val jwt = builder(
         *     subject = TokenType.ACCESS,
         *     userId = "user123",
         *     userRole = MyRole.ADMIN,
         *     userPermissions = listOf(MyPermission.READ, MyPermission.WRITE),
         *     issuer = "my-app",
         *     audience = setOf("my-app-users"),
         *     expiration = Instant.now().plus(1, ChronoUnit.HOURS)
         * ).compact()
         * ```
         *
         * ## Generic Parameters
         * - `RoleT` – Enum type implementing [RoleAccessPolicy], representing the user's role
         * - `TokenT` – Enum type implementing [TokenAccessPolicy], representing the token type
         * - `PermissionT` – Enum type representing the user's permissions
         *
         * @param subject The token type (e.g., access, refresh)
         * @param userId Unique identifier of the user for whom the JWT is issued
         * @param userRole Role of the user, implementing [RoleAccessPolicy]
         * @param userPermissions List of user permissions (fine-grained access control)
         * @param issuer JWT issuer (`iss` claim)
         * @param audience JWT audience (`aud` claim)
         * @param expiration Expiration timestamp (`exp` claim)
         *
         * @return A configured [JwtBuilder] instance ready to build a signed JWT.
         */
		fun <RoleT, TokenT, PermissionT> builder(
            subject: TokenT,
			userId : String,
			userRole : RoleT,
            userPermissions : List<PermissionT>,
            issuer : String,
            audience : Set<String>,
            expiration : Instant
		) : io.ghaylan.springboot.security.utils.jwt.JwtBuilder where
                RoleT: Enum<RoleT>, RoleT : RoleAccessPolicy,
                TokenT : Enum<TokenT>, TokenT : TokenAccessPolicy,
                PermissionT: Enum<PermissionT>
		{
			val builder = Jwts.builder()
				.claim(JwtUtils.KEY_USER_ID, userId)
				.claim(JwtUtils.KEY_USER_ROLE, userRole.name)
				.claim(JwtUtils.KEY_USER_PERMISSIONS, userPermissions.map { it.name })
                .subject(subject.name)
                .issuer(issuer)
                .audience().add(audience).and()
				.issuedAt(Date())
                .expiration(Date.from(expiration))
			
			return JwtBuilder(builder)
		}
	}


    /**
     * Sets the JWT ID (jti claim) to uniquely identify the token.
     *
     * @param value The unique identifier for the token.
     * @return This [JwtBuilder] for method chaining.
     */
	fun setId(value : String) : io.ghaylan.springboot.security.utils.jwt.JwtBuilder
	{
		builder.id(value)

		return this
	}


    /**
     * Sets a custom claim under a specified key.
     *
     * @param key The claim name.
     * @param value The claim value.
     * @return This [JwtBuilder] for method chaining.
     */
	fun setClaim(key : String, value : Any) : io.ghaylan.springboot.security.utils.jwt.JwtBuilder
	{
		builder.claim(key, value)
		return this
	}


    /**
     * Sets multiple custom claims using a builder-style lambda.
     *
     * @param claimsBuilder A lambda with receiver on [HashMap] to define claims.
     * @return This [JwtBuilder] for method chaining.
     */
    fun setClaims(claimsBuilder : HashMap<String, Any?>.() -> Unit) : io.ghaylan.springboot.security.utils.jwt.JwtBuilder
    {
        val claims = HashMap<String, Any?>().apply(claimsBuilder)
        return setClaims(claims)
    }


    /**
     * Sets multiple custom claims at once.
     *
     * @param claims A map containing claim names and their corresponding values. Values can be null.
     * @return This [JwtBuilder] for method chaining.
     */
    fun setClaims(claims : Map<String, Any?>) : io.ghaylan.springboot.security.utils.jwt.JwtBuilder
    {
        builder.claims(claims)
        return this
    }


    /**
     * Enables Base64 payload encoding for the JWT.
     *
     * @return This [JwtBuilder] for method chaining.
     */
	fun encodePayload() : io.ghaylan.springboot.security.utils.jwt.JwtBuilder
	{
		builder.encodePayload(true)

		return this
	}


    /**
     * Enables compression for the JWT payload using Deflate compression.
     *
     * @return This [JwtBuilder] for method chaining.
     */
	fun compress() : io.ghaylan.springboot.security.utils.jwt.JwtBuilder
	{
        builder.compressWith(Jwts.ZIP.DEF)

		return this
	}


    /**
     * Signs the JWT using the provided private key with RS256 algorithm and returns a compact string.
     *
     * @param privateKey The [PrivateKey] used for signing.
     * @return The signed JWT as a compact string.
     */
	fun build(privateKey : PrivateKey) : String
	{
        return builder.signWith(privateKey, Jwts.SIG.RS256).compact()
	}
}