package io.ghaylan.springboot.security.utils.apikey

import java.math.BigInteger
import kotlin.text.iterator

/**
 * Utility object for Base62 encoding and decoding.
 *
 * Base62 is a compact, URL-safe encoding scheme using the characters:
 * 0-9, A-Z, a-z (62 symbols total).
 *
 * This is primarily used for encoding binary data (like encrypted API keys)
 * into a string that is safe for URLs and filenames.
 *
 * ## Features
 * - Deterministic encoding/decoding of arbitrary byte arrays.
 * - Throws an exception on invalid input during decoding.
 *
 * ## Example Usage
 * ```kotlin
 * val originalBytes = byteArrayOf(1, 2, 3, 4)
 * val encoded = Base62.encode(originalBytes)
 * val decoded = Base62.decode(encoded)
 * assert(decoded.contentEquals(originalBytes))
 * ```
 */
internal object Base62
{
    private const val ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    private val ALPHABET_LENGTH = ALPHABET.length.toBigInteger()


    /**
     * Encodes a byte array into a Base62 string.
     *
     * @param input Byte array to encode
     * @return Base62-encoded string representation
     */
    fun encode(input: ByteArray): String
    {
        var value = BigInteger(1, input)
        val result = StringBuilder()

        while (value > BigInteger.ZERO)
        {
            val rem = value.mod(ALPHABET_LENGTH).toInt()
            result.insert(0, ALPHABET[rem])
            value = value.divide(ALPHABET_LENGTH)
        }

        return if (result.isEmpty()) ALPHABET[0].toString() else result.toString()
    }


    /**
     * Decodes a Base62 string back into a byte array.
     *
     * @param input Base62 string to decode
     * @return Original byte array
     * @throws IllegalArgumentException If the input contains invalid Base62 characters
     */
    fun decode(input: String) : ByteArray
    {
        var value = BigInteger.ZERO

        for (char in input)
        {
            val index = ALPHABET.indexOf(char)
            require(index >= 0) { "Invalid character '$char' in Base62 string." }
            value = value.multiply(ALPHABET_LENGTH).add(index.toBigInteger())
        }

        val bytes = value.toByteArray()

        return if (bytes.firstOrNull() == 0.toByte()) bytes.drop(1).toByteArray() else bytes
    }
}