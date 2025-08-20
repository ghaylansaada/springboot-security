package io.ghaylan.springboot.security.utils

import org.springframework.http.HttpHeaders
import org.springframework.http.server.reactive.ServerHttpRequest

/**
 * Utility functions for extracting information from reactive ServerHttpRequest.
 *
 * This utility class provides extension functions for ServerHttpRequest to extract
 * common request information in a reactive environment, replacing the servlet-based
 * request utilities used in the MVC version.
 *
 * ## Features
 * - **IP Address Extraction**: Supports forwarded headers and direct remote address
 * - **User Agent Extraction**: Extracts browser/client information
 * - **Language Detection**: Parses Accept-Language headers
 * - **Query Parameter Extraction**: Reactive-friendly parameter parsing
 * - **Header Information**: Comprehensive header extraction
 */
object ReactiveRequestUtils
{
    const val HEADER_KEY_IP_ADDRESS : String = "X-Forwarded-For"
    const val HEADER_KEY_SECRET_CODE : String = "X-Secret-Code"
    const val HEADER_KEY_REQUEST_ID : String = "X-Request-ID"


    /**
     * Extracts the client IP address from the reactive request.
     *
     * Checks forwarded headers first, then falls back to remote address.
     *
     * @return The client IP address, or "unknown" if not available
     */
    fun ServerHttpRequest.extractIpAddress(): String
    {
        return headers.getFirst(HEADER_KEY_IP_ADDRESS)
            ?: remoteAddress?.address?.hostAddress
            ?: "unknown"
    }


    /**
     * Extracts the user agent from the reactive request.
     *
     * @return The user agent string, or null if not available
     */
    fun ServerHttpRequest.extractUserAgent(): String?
    {
        return headers.getFirst(HttpHeaders.USER_AGENT)
    }


    /**
     * Extracts the secret code header from the request.
     *
     * @return The secret code, or null if not available
     */
    fun ServerHttpRequest.extractSecretCode(): String?
    {
        return headers.getFirst(HEADER_KEY_SECRET_CODE)?.trim()
    }


    /**
     * Extracts the request ID header from the request.
     *
     * @return The request ID, or null if not available
     */
    fun ServerHttpRequest.extractRequestId(): String?
    {
        return headers.getFirst(HEADER_KEY_REQUEST_ID)?.trim()
    }


    /**
     * Extracts the Authorization header value.
     *
     * @return The authorization header value, or null if not present
     */
    fun ServerHttpRequest.extractAuthorizationHeader(): String?
    {
        return headers.getFirst(HttpHeaders.AUTHORIZATION)
    }


    /**
     * Extracts credentials from the Authorization header for a specific scheme.
     *
     * @param scheme The authorization scheme to extract credentials for
     * @return The credentials part of the authorization header, or null if not found
     */
    fun ServerHttpRequest.extractCredentials(scheme: String): String?
    {
        val authHeader = extractAuthorizationHeader()

        return if (authHeader?.startsWith(scheme, ignoreCase = true) == true)
        {
            authHeader.removePrefix(scheme).trim().takeIf { it.isNotBlank() }
        }
        else null
    }
}