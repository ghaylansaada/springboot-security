package io.ghaylan.springboot.security

import io.ghaylan.springboot.security.extractor.ApiKeyAuthExtractor
import io.ghaylan.springboot.security.extractor.BasicAuthExtractor
import io.ghaylan.springboot.security.extractor.BearerAuthExtractor
import io.ghaylan.springboot.security.extractor.HmacAuthExtractor
import io.ghaylan.springboot.security.model.AuthScheme
import io.ghaylan.springboot.security.ratelimit.RateLimitManager
import io.ghaylan.springboot.security.utils.apikey.ApiKeyManager
import io.ghaylan.springboot.security.utils.hmac.HmacManager
import io.ghaylan.springboot.security.utils.jwt.UserJwtReader
import io.ghaylan.springboot.security.utils.jwt.SystemJwtManager
import org.springframework.context.ApplicationContext

/**
 * Validates that required security beans are available based on configuration.
 *
 * This validation object ensures that all necessary beans for the configured
 * authentication schemes and features are present in the application context.
 * It's typically called during application startup to catch configuration
 * issues early.
 *
 * ## Validation Rules
 * - **Rate Limiting**: If rate limiting is enabled, [RateLimitManager] must be available
 * - **Feign Clients**: If Feign clients are used, [SystemJwtManager] must be available
 * - **Bearer Authentication**: Requires [UserJwtReader], [SystemJwtManager], and [BearerAuthExtractor]
 * - **API Key Authentication**: Requires [ApiKeyManager] and [ApiKeyAuthExtractor]
 * - **Basic Authentication**: Requires [BasicAuthExtractor]
 * - **HMAC Authentication**: Requires [HmacManager] and [HmacAuthExtractor]
 *
 * ## Usage
 * ```kotlin
 * SecurityConfigValidation.validateRequiredBeans(applicationContext, securityContainer)
 * ```
 */
object SecurityConfigValidation
{

    /**
     * Validates that all required beans for the current security configuration are available.
     *
     * This method checks the application context and security container to determine
     * which authentication schemes and features are being used, then verifies that
     * all corresponding required beans are present.
     *
     * @param appContext The Spring application context to check for beans
     * @param securityContainer The security container with configuration information
     * @throws IllegalArgumentException if required beans are missing
     */
    fun validateRequiredBeans(appContext: ApplicationContext, securityContainer: SecurityContainer<*, *>)
    {
        // Validate rate limiting configuration
        if (securityContainer.hasRateLimiter())
        {
            validateBeanExists<RateLimitManager>(appContext, "Rate limiting is enabled, but ${RateLimitManager::class.java.simpleName} is not available")
        }

        validateBeanExists<SystemJwtManager<*>>(appContext, "${SystemJwtManager::class.java.simpleName} is not available")

        // Validate authentication scheme configurations
        val usedSchemes = securityContainer.collectUsedSecuritySchemes()
        validateAuthenticationSchemes(appContext, usedSchemes)
    }


    /**
     * Validates that all required beans for the specified authentication schemes are available.
     *
     * @param appContext The Spring application context to check for beans
     * @param usedSchemes The authentication schemes being used
     * @throws IllegalArgumentException if required beans are missing
     */
    private fun validateAuthenticationSchemes(appContext: ApplicationContext, usedSchemes: List<AuthScheme>)
    {
        if (usedSchemes.contains(AuthScheme.BEARER))
        {
            validateBeanExists<UserJwtReader>(appContext, "Bearer authentication is used, but ${UserJwtReader::class.java.simpleName} is not available")
            validateBeanExists<SystemJwtManager<*>>(appContext, "Bearer authentication is used, but ${SystemJwtManager::class.java.simpleName} is not available")
            validateBeanExists<BearerAuthExtractor>(appContext, "Bearer authentication is used, but ${BearerAuthExtractor::class.java.simpleName} is not available")
        }

        if (usedSchemes.contains(AuthScheme.API_KEY))
        {
            validateBeanExists<ApiKeyManager>(appContext, "API key authentication is used, but ${ApiKeyManager::class.java.simpleName} is not available")
            validateBeanExists<ApiKeyAuthExtractor>(appContext, "API key authentication is used, but ${ApiKeyAuthExtractor::class.java.simpleName} is not available")
        }

        if (usedSchemes.contains(AuthScheme.BASIC))
        {
            validateBeanExists<BasicAuthExtractor>(appContext, "Basic authentication is used, but ${BasicAuthExtractor::class.java.simpleName} is not available")
        }

        if (usedSchemes.contains(AuthScheme.HMAC))
        {
            validateBeanExists<HmacManager>(appContext, "HMAC authentication is used, but ${HmacManager::class.java.simpleName} is not available")
            validateBeanExists<HmacAuthExtractor>(appContext, "HMAC authentication is used, but ${HmacAuthExtractor::class.java.simpleName} is not available")
        }
    }


    /**
     * Validates that a bean of the specified type exists in the application context.
     *
     * @param T The type of bean to check for
     * @param appContext The Spring application context
     * @param errorMessage The error message to include in the exception
     * @throws IllegalArgumentException if the bean is not found
     */
    private inline fun <reified T> validateBeanExists(appContext: ApplicationContext, errorMessage: String)
    {
        require(appContext.getBeansOfType(T::class.java).isNotEmpty()) { errorMessage }
    }
}