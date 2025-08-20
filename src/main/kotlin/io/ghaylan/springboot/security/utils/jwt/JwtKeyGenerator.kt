package io.ghaylan.springboot.security.utils.jwt

import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Utility object for generating cryptographic keys from Base64-encoded strings.
 *
 * Provides helper methods for creating [PrivateKey] and [PublicKey] instances
 * from PEM or Base64-encoded key strings, using the algorithm defined in [JwtUtils.KEY_FACTORY_ALGORITHM].
 *
 * ## Features
 * - Supports PEM-format and raw Base64 strings.
 * - Automatically strips standard PEM headers/footers and line breaks.
 * - Returns fully initialized [PrivateKey] or [PublicKey] instances.
 *
 * ## Security Considerations
 * - Ensure key strings are securely stored and never hard-coded in source code.
 * - Validate keys against expected algorithms and formats before use.
 * - Protect private keys with proper access control and encryption at rest.
 */
object JwtKeyGenerator
{

    /**
     * Generates a [PrivateKey] from a Base64-encoded string in PKCS#8 format.
     *
     * This method strips PEM headers/footers ("-----BEGIN PRIVATE KEY-----"/"-----END PRIVATE KEY-----")
     * and all line breaks before decoding.
     *
     * Example usage:
     * ```kotlin
     * val privateKey = JwtKeyGenerator.generatePrivateKey(privateKeyString)
     * ```
     *
     * @param key Base64-encoded private key string, typically in PKCS#8 PEM format.
     * @return A [PrivateKey] instance corresponding to the input string.
     * @throws NoSuchAlgorithmException If the algorithm specified in [JwtUtils.KEY_FACTORY_ALGORITHM] is not available.
     * @throws InvalidKeySpecException If the key specification is invalid or corrupted.
     * @throws IllegalArgumentException If the input string cannot be Base64-decoded properly.
     */
	fun generatePrivateKey(key : String) : PrivateKey
	{
		val privateKey : String = key.replace("\n", "")
			.replace("-----BEGIN PRIVATE KEY-----", "")
			.replace("-----END PRIVATE KEY-----", "")

		val keyFactory : KeyFactory = KeyFactory.getInstance(JwtUtils.KEY_FACTORY_ALGORITHM)

		val encodedKey : ByteArray = Base64.getDecoder().decode(privateKey)

		val keySpecPKCS8 = PKCS8EncodedKeySpec(encodedKey)

		return keyFactory.generatePrivate(keySpecPKCS8)
	}


    /**
     * Generates a [PublicKey] from a Base64-encoded string in X.509 format.
     *
     * This method strips PEM headers/footers ("-----BEGIN PUBLIC KEY-----"/"-----END PUBLIC KEY-----")
     * and all line breaks before decoding.
     *
     * Example usage:
     * ```kotlin
     * val publicKey = JwtKeyGenerator.generatePublicKey(publicKeyString)
     * ```
     *
     * @param key Base64-encoded public key string, typically in X.509 PEM format.
     * @return A [PublicKey] instance corresponding to the input string.
     * @throws NoSuchAlgorithmException If the algorithm specified in [JwtUtils.KEY_FACTORY_ALGORITHM] is not available.
     * @throws InvalidKeySpecException If the key specification is invalid or corrupted.
     * @throws IllegalArgumentException If the input string cannot be Base64-decoded properly.
     */
	fun generatePublicKey(key : String) : PublicKey
	{
		val publicKey : String = key.replace("\n", "")
			.replace("-----BEGIN PUBLIC KEY-----", "")
			.replace("-----END PUBLIC KEY-----", "")

		val keyFactory : KeyFactory = KeyFactory.getInstance(JwtUtils.KEY_FACTORY_ALGORITHM)

		val encodedKey : ByteArray = Base64.getDecoder().decode(publicKey)

		val keySpecPKCS8 = X509EncodedKeySpec(encodedKey)

		return keyFactory.generatePublic(keySpecPKCS8)
	}
}