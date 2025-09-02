package io.ghaylan.springboot.security.utils.jwt

import io.ghaylan.springboot.security.exception.HttpStatusCode
import io.ghaylan.springboot.security.exception.SecurityViolationException
import io.ghaylan.springboot.security.extractor.RawExtractedAuth
import io.ghaylan.springboot.security.model.role.RoleAccessPolicy
import io.ghaylan.springboot.security.model.token.TokenAccessPolicy
import java.security.PrivateKey
import java.security.PublicKey
import java.time.Instant

/**
 * Manager for **system-level JWT tokens** used in **inter-service communication**.
 *
 * This utility generates **short-lived JWT tokens** that are strictly bound to:
 * - A specific HTTP method (GET, POST, etc.)
 * - A specific URI path
 * - A specific destination service
 *
 * Each token is **request-specific** and cannot be reused for another endpoint or service.
 * This is enforced by encoding the destination service, method, and URI into the token's audience claim.
 *
 * Token contents include:
 * - Predefined system user ID: `"system"`
 * - Internal role
 * - Expiration timestamp (2 minutes)
 * - Audience claim: `destinationServiceName::method::uri`
 * - Issuer: `currentServiceName`
 *
 * ## Security Benefits
 * - Tokens are **short-lived**, minimizing misuse if intercepted.
 * - Tokens are **request-specific**, preventing replay attacks on other requests.
 * - Audience claim ensures the token is validated only for the intended service, method, and URI.
 * - RS256 signing guarantees integrity and authenticity.
 *
 * @param RoleT Enum type representing internal roles, implementing [RoleAccessPolicy].
 *
 * @property publicKey Public key used to validate JWT signatures.
 * @property privateKey Private key used to sign JWTs.
 * @property internalRole The internal role assigned to system tokens.
 * @property currentServiceName The name of the service issuing tokens.
 */
class SystemJwtManager<RoleT, TokenT>(
	publicKey : PublicKey,
	private val privateKey : PrivateKey,
	private val internalRole : RoleT,
    private val internalSubject: TokenT,
	private val currentServiceName : String,
)  where RoleT: Enum<RoleT>, RoleT : RoleAccessPolicy, TokenT: Enum<TokenT>, TokenT : TokenAccessPolicy
{
	private val jwtParser = JwtUtils.getParser(publicKey)
	private val delimiter : String = "::"


    /**
     * Generates a signed JWT token for a **specific inter-service request**.
     *
     * The token is bound to the exact request:
     * - HTTP method
     * - URI
     * - Destination service
     *
     * Only the destination service encoded in the audience can validate this token successfully.
     *
     * @param uri The URI path of the request to be called.
     * @param method The HTTP method (GET, POST, etc.) for the request.
     * @param destinationServiceName The name of the service that will receive the request.
     * @return A signed JWT as a compact string, valid for 2 minutes.
     */
	fun generate(
		uri : String,
		method : String,
		destinationServiceName : String
	) : String
	{
		// Set expiration to 2 minutes from now
		val expiration = Instant.now().plusSeconds(120)

        val audience = buildAudience(
            serviceName = destinationServiceName,
            requestMethod = method,
            requestUri = uri)
		
		// Build and sign the JWT
		return JwtBuilder.builder(
            subject = internalSubject,
			userId = "system",
			userRole = internalRole,
			userPermissions = emptyList(),
            issuer = currentServiceName,
            audience = setOf(audience),
            expiration = expiration
        ).build(privateKey)
	}


    /**
     * Validates a system JWT token on the **destination service**.
     *
     * Validation checks:
     * 1. Signature correctness.
     * 2. Audience contains the exact `destinationServiceName::method::uri`.
     * 3. Ensures token cannot be used for another service, method, or URI.
     *
     * If validation fails, a [SecurityViolationException] is thrown.
     *
     * @param jwt The JWT string received from the calling service.
     * @param requestMethod The HTTP method of the incoming request.
     * @param requestUri The URI path of the incoming request.
     * @return A [RawExtractedAuth] object containing system user information.
     * @throws SecurityViolationException If the token is invalid or used for the wrong request/service.
     */
	fun resolve(
		jwt : String,
		requestMethod : String,
		requestUri : String,
	) : RawExtractedAuth?
	{
		val claims = jwtParser.parseSignedClaims(jwt)?.payload ?: return null

        val currentAudience = buildAudience(
            serviceName = currentServiceName,
            requestMethod = requestMethod,
            requestUri = requestUri)

        if (!claims.audience.contains(currentAudience)) {
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: invalid audience for internal JWT.")
        }

		return RawExtractedAuth(
			id = claims[JwtUtils.KEY_USER_ID]?.toString() ?: return null,
			role = claims[JwtUtils.KEY_USER_ROLE]?.toString() ?: return null,
			name = claims[JwtUtils.KEY_USER_NAME]?.toString(),
            tokenType = claims.subject,
			permissions = null,
			credentials = null)
	}


    private fun buildAudience(
        serviceName: String,
        requestMethod: String,
        requestUri: String,
    ): String = "$serviceName$delimiter$requestMethod$delimiter$requestUri"
}