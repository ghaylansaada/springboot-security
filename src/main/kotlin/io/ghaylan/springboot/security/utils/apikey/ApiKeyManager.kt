package io.ghaylan.springboot.security.utils.apikey

import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.security.spec.KeySpec
import java.time.Duration
import java.time.Instant
import java.time.Period
import java.time.ZoneOffset
import java.time.temporal.TemporalAmount
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Utility class for generating, encrypting, and decrypting API keys.
 *
 * This utility uses **AES-GCM encryption** with **PBKDF2 key derivation** and
 * **Base62 encoding** to create secure, URL-safe API keys that encode:
 * - User ID
 * - User role
 * - User permissions
 * - Expiration timestamp
 *
 * ## Security Features
 * - AES-GCM encryption ensures confidentiality and integrity.
 * - PBKDF2 with salt protects against brute-force key attacks.
 * - SecureRandom IV ensures uniqueness for each encryption.
 * - Base62 encoding produces compact, URL-safe API keys.
 * - Optional prefix validation allows scoping keys per service.
 *
 * ## Example Usage
 * ```kotlin
 * val apiKeyManager = ApiKeyManager(saltString = "secureSalt123", prefix = "myapp_")
 *
 * // Generate API key valid for 1 year, with permissions
 * val apiKey = apiKeyManager.generateApiKey(
 *     userId = "user123",
 *     role = "ADMIN",
 *     permissions = listOf("READ_REPORTS", "MANAGE_USERS"),
 *     secret = "user-secret",
 *     expiresAt = Instant.now().plus(Period.ofYears(1)))
 *
 * // Decrypt and validate API key
 * val decoded = apiKeyManager.decryptApiKey(apiKey, secret = "user-secret")
 * println(decoded.userId)        // "user123"
 * println(decoded.permissions)   // ["READ_REPORTS", "MANAGE_USERS"]
 * ```
 *
 * @param saltString Salt string for PBKDF2 key derivation (must be ≥ 8 chars)
 * @param prefix Service-specific prefix to identify API keys (e.g., "myapp_")
 */
class ApiKeyManager(saltString : String, private val prefix : String)
{
    companion object
    {
        private const val ITERATIONS = 65_536
        private const val KEY_LENGTH = 256  // bits
        private const val IV_LENGTH = 12    // GCM recommended IV = 12 bytes
        private const val TAG_LENGTH = 96   // GCM tag length in bits
        private const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256"
        private const val SECRET_KEY_SPEC_ALGORITHM = "AES"
        private const val DELIMITER = "|"
        private val CHARSET : Charset = StandardCharsets.UTF_8
    }

    private val salt : ByteArray


    init
    {
        require(saltString.length >= 8 ) { "salt must not be < 8 characters" }
        require(prefix.isNotBlank()) { "key prefix must not be empty or blank" }

        salt = saltString.toByteArray(CHARSET)
    }


    /**
     * Generates a new encrypted API key for a user.
     *
     * @param userId User identifier (non-blank)
     * @param role User role (non-blank)
     * @param permissions List of user permissions (may be empty but not null)
     * @param secret User-specific secret used for key derivation (non-blank)
     * @param expiresAt Expiration time for the API key (must be in the future)
     * @return Encrypted, Base62-encoded API key string with service prefix
     * @throws IllegalArgumentException If any input is invalid
     */
    fun generateApiKey(
        userId : String,
        role : String,
        permissions : List<String>,
        secret : String,
        expiresAt : Instant = Instant.now().plusTemporalAmount(Period.ofYears(50))
    ) : String
    {
        require(userId.isNotBlank()) { "userId must not be blank" }
        require(role.isNotBlank()) { "role must not be blank" }
        require(secret.isNotBlank()) { "secret must not be blank" }
        require(expiresAt.isAfter(Instant.now())) { "expiration must be in the future" }

        val plainText = setOf(
            userId,
            role,
            permissions.joinToString(","),
            expiresAt.epochSecond.toString()
        ).joinToString(DELIMITER).toByteArray(CHARSET)

        val iv = ByteArray(IV_LENGTH).apply { SecureRandom().nextBytes(this) }

        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(secret), GCMParameterSpec(TAG_LENGTH, iv))
        val encrypted = cipher.doFinal(plainText)

        val buffer = ByteBuffer.allocate(iv.size + encrypted.size)
        buffer.put(iv)
        buffer.put(encrypted)

        return prefix + Base62.encode(buffer.array())
    }


    /**
     * Decrypts and validates an API key.
     *
     * @param apiKey Encrypted API key string
     * @param secret Secret used to derive the encryption key
     * @return [DecodedApiKey] containing userId, role, permissions, and expiration
     * @throws IllegalArgumentException If prefix is invalid, format is corrupted, or secret is wrong
     */
    fun decryptApiKey(
        apiKey : String,
        secret : String,
    ) : DecodedApiKey
    {
        require(secret.isNotBlank()) { "secret must not be blank" }
        require(apiKey.startsWith(prefix)) { "API key missing required prefix" }

        val encoded = apiKey.removePrefix(prefix)
        val decoded = Base62.decode(encoded)

        require(decoded.size > IV_LENGTH) { "Invalid API key format: too short" }

        val iv = decoded.copyOfRange(0, IV_LENGTH)
        val cipherText = decoded.copyOfRange(IV_LENGTH, decoded.size)

        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(secret), GCMParameterSpec(TAG_LENGTH, iv))
        val decrypted = cipher.doFinal(cipherText)
        val plainText = String(decrypted, CHARSET)

        val parts = plainText.split(DELIMITER)
        require(parts.size == 4) { "Invalid decrypted format: expected userId, role, expiration" }

        val (userId, role, permissionsAsStr, expiresAtStr) = parts

        val expiresAt = Instant.ofEpochSecond(expiresAtStr.toLongOrNull() ?: error("Invalid expiration timestamp"))

        val permissions = runCatching {
            permissionsAsStr.split(",").toSet()
        }.getOrDefault(emptySet())

        return DecodedApiKey(userId, role, permissions, expiresAt)
    }


    /**
     * Derives an AES key from a secret string using PBKDF2 with the configured salt.
     *
     * @param secret User-specific secret string
     * @return [SecretKeySpec] ready for AES-GCM encryption/decryption
     */
    private fun deriveKey(secret: String) : SecretKeySpec
    {
        val factory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITHM)
        val spec: KeySpec = PBEKeySpec(secret.toCharArray(), salt, ITERATIONS, KEY_LENGTH)
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, SECRET_KEY_SPEC_ALGORITHM)
    }


    /**
     * Adds a TemporalAmount (Duration or Period) to an Instant.
     *
     * @param amount Duration or Period to add
     * @return New Instant after adding the specified amount
     * @throws IllegalArgumentException If TemporalAmount type is unsupported
     */
    private fun Instant.plusTemporalAmount(amount: TemporalAmount): Instant
    {
        return when (amount)
        {
            is Duration -> this.plus(amount)
            is Period -> this.atZone(ZoneOffset.UTC).plus(amount).toInstant()
            else -> throw IllegalArgumentException("Unsupported TemporalAmount: ${amount::class}")
        }
    }


    /**
     * Represents the decrypted contents of an API key.
     *
     * @property userId User identifier embedded in the API key
     * @property role User role embedded in the API key
     * @property permissions User permissions embedded in the API key
     * @property expiresAt Expiration timestamp
     */
    data class DecodedApiKey(
        val userId : String,
        val role : String,
        val permissions : Set<String>,
        val expiresAt : Instant)
}