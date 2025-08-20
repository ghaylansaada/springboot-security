package io.ghaylan.springboot.security.ratelimit

import io.ghaylan.springboot.security.model.SecuritySchema
import kotlinx.coroutines.reactive.awaitFirstOrNull
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import org.springframework.data.redis.core.script.DefaultRedisScript
import java.time.Duration
import java.time.Instant

/**
 * Redis-based rate limiting and session revocation manager.
 *
 * This component provides two core security features:
 *
 * 1. **Distributed Rate Limiting**
 *    - Implements per-user, per-IP, and global request throttling using a
 *      sliding-window algorithm backed by Redis sorted sets.
 *    - Atomic Lua scripts ensure consistency and prevent race conditions
 *      in distributed environments.
 *    - Useful for preventing brute-force login attempts, abusive scraping,
 *      or protecting expensive endpoints from overload.
 *
 * 2. **Session and Token Revocation**
 *    - Provides immediate invalidation of active sessions and authorization tokens,
 *      propagated across all application instances via Redis.
 *    - Supports two revocation levels:
 *
 *      - **User-level revocation (`revokeUserId`)**:
 *        Blocks an entire user account from making requests, regardless of which
 *        tokens the user presents. This is typically used when an admin suspends
 *        an account, fraud is detected, or an emergency lockout is needed.
 *
 *      - **Token-level revocation (`revokeAuth`)**:
 *        Invalidates a specific token (e.g., JWT, API key) even if it has not expired.
 *        This is useful for explicit logout, password reset flows, or when a token
 *        is leaked/compromised but the user account itself should remain active.
 *
 *    - Revocations are temporary: both user and token revocations are stored with
 *      a configurable TTL (default: **1 hour**). This prevents unbounded Redis growth
 *      while ensuring revoked sessions cannot be reused during the suspension window.
 *
 * ---
 * ## Example Usage
 * ```kotlin
 * val manager = RateLimitManager(redisTemplate)
 *
 * // Rate limiting
 * if (manager.isMaxAttemptsReachedByIp(schema, "192.168.1.1")) {
 *     throw RateLimitExceededException()
 * }
 *
 * // Session revocation
 * manager.revokeUserId("user-123")   // Suspend a full user account
 * manager.revokeAuth("jwt-token-xyz") // Revoke one specific token
 *
 * val isSuspended = manager.isSessionSuspended("user-123", "jwt-token-xyz")
 * ```
 *
 * ---
 * @property redisTemplate Reactive Redis template for data operations
 */
class RateLimitManager(private val redisTemplate : ReactiveStringRedisTemplate)
{
	companion object
	{
		private const val PREFIX_AUTH = "revoked_auth"
		private const val PREFIX_USER = "revoked_user"
		private const val PREFIX_RATE = "rate"
		private val RATE_LIMIT_LUA_SCRIPT = """
			redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1])
			local count = redis.call('ZCARD', KEYS[1])
			if count < tonumber(ARGV[2]) then
				redis.call('ZADD', KEYS[1], ARGV[3], ARGV[3])
				redis.call('PEXPIRE', KEYS[1], ARGV[4])
				return 0
			else
				return 1
			end
		""".trimIndent()
		private val RATE_LIMIT_SCRIPT_OBJECT = DefaultRedisScript(RATE_LIMIT_LUA_SCRIPT, Long::class.java)
		private val SESSION_REVOCATION_DURATION = Duration.ofHours(1)
	}


    /**
     * Determines whether a specific IP address has exceeded the configured rate limit for an endpoint.
     *
     * This method enforces **per-IP sliding window rate limiting**. Each request is timestamped
     * and stored in Redis, with old entries automatically evicted as the window moves forward.
     *
     * Typical use cases:
     * - Protecting login endpoints against brute-force attacks.
     * - Mitigating abusive traffic from a single client machine.
     *
     * @param securitySchema Security configuration containing rate limit rules (maxAttempts, duration, timeUnit).
     *                       If no rate limit is defined in the schema, this method always returns `false`.
     * @param ipAddress The client IP address to evaluate.
     * @return `true` if the IP has already reached or exceeded its allowed attempts in the current window,
     *         `false` if it is still under the limit.
     */
    suspend fun isMaxAttemptsReachedByIp(
        securitySchema : SecuritySchema<*, *>,
        ipAddress : String,
    ) : Boolean
    {
        val key : String = buildKeyForRateLimit(
            method = securitySchema.method.name(),
            uri = securitySchema.uri,
            ipAddress = ipAddress,
            userId = null,
            strategy = RateLimitStrategy.IP)

        return isMaxAttemptsReached(securitySchema, key)
    }


    /**
     * Determines whether the **global rate limit** for an endpoint has been exceeded across all clients.
     *
     * This strategy applies rate limiting **independently of user identity or IP address**.
     * All requests to the same method+URI share the same quota.
     *
     * Typical use cases:
     * - Preventing system-wide abuse of expensive or high-traffic endpoints.
     * - Limiting overall throughput for sensitive APIs.
     *
     * @param securitySchema Security configuration containing rate limit rules.
     *                       If no rate limit is defined, this method always returns `false`.
     * @return `true` if the shared quota has been exhausted, otherwise `false`.
     */
    suspend fun isMaxAttemptsReachedForAll(
        securitySchema : SecuritySchema<*, *>
    ) : Boolean
    {
        val key : String = buildKeyForRateLimit(
            method = securitySchema.method.name(),
            uri = securitySchema.uri,
            ipAddress = null,
            userId = null,
            strategy = RateLimitStrategy.ALL)

        return isMaxAttemptsReached(securitySchema, key)
    }


    /**
     * Determines whether a specific user has exceeded the configured rate limit for an endpoint.
     *
     * This method enforces **per-user sliding window rate limiting**. Each user’s requests
     * are counted independently, ensuring fair usage across multiple accounts.
     *
     * Typical use cases:
     * - Preventing a single account from spamming or monopolizing API resources.
     * - Applying stricter quotas to authenticated user operations (e.g., uploads).
     *
     * @param securitySchema Security configuration containing rate limit rules.
     *                       If no rate limit is defined, this method always returns `false`.
     * @param userId Unique user identifier to evaluate (must be non-null).
     * @return `true` if the user has reached or exceeded their allowed attempts in the current window,
     *         otherwise `false`.
     */
    suspend fun isMaxAttemptsReachedByUser(
        securitySchema : SecuritySchema<*, *>,
        userId : String
    ) : Boolean
    {
        val key : String = buildKeyForRateLimit(
            method = securitySchema.method.name(),
            uri = securitySchema.uri,
            ipAddress = null,
            userId = userId,
            strategy = RateLimitStrategy.USER)

        return isMaxAttemptsReached(securitySchema, key)
    }


    /**
     * Executes the sliding window rate-limiting algorithm for the given Redis key.
     *
     * This method uses an **atomic Redis Lua script** to:
     * 1. Remove expired request timestamps outside the sliding window.
     * 2. Count remaining requests within the window.
     * 3. Add the current request timestamp if under the limit, or reject if quota exceeded.
     * 4. Refresh the key’s TTL to the window length (+5s buffer).
     *
     * Notes:
     * - If `securitySchema.rateLimit` is `null`, no limit is applied and the method returns `false`.
     * - The result is deterministic and consistent across distributed application instances.
     *
     * @param securitySchema Security configuration for the endpoint.
     * @param key Redis key uniquely identifying the rate limit bucket (per-IP, per-user, or global).
     * @return `true` if the rate limit has been exceeded, `false` otherwise.
     */
    private suspend fun isMaxAttemptsReached(
        securitySchema : SecuritySchema<*, *>,
        key : String
    ) : Boolean
    {
        // No rate limit applied if null
        securitySchema.rateLimit ?: return false

        val now = Instant.now().toEpochMilli()

        val windowSize = Duration.of(securitySchema.rateLimit.duration, securitySchema.rateLimit.timeUnit)

        val windowStart = now - windowSize.toMillis()

        val args = listOf(
            windowStart.toString(),								// ARGV[1]: Old timestamp
            securitySchema.rateLimit.maxAttempts.toString(),	// ARGV[2]: Max attempts
            now.toString(),                              		// ARGV[3]: Current timestamp
            (windowSize.toMillis() + 5000).toString())			// ARGV[4]: TTL in ms

        return redisTemplate
            .execute(RATE_LIMIT_SCRIPT_OBJECT, listOf(key), args)
            .awaitFirstOrNull() == 1L
    }


    /**
     * Immediately revokes a specific authorization token for a fixed duration (default: 1 hour).
     *
     * After revocation:
     * - Any request authenticated with this token is rejected until the revocation entry expires.
     * - The revocation is propagated across all application nodes via Redis.
     *
     * Typical use cases:
     * - Explicit logout of a session.
     * - Invalidating tokens after password change or reset.
     * - Blocking a compromised token without disabling the entire user account.
     *
     * @param auth Authorization token (e.g., JWT, API key) to revoke.
     */
	suspend fun revokeAuth(auth : String)
	{
		redisTemplate.opsForValue()
            .set("$PREFIX_AUTH::$auth", "1", SESSION_REVOCATION_DURATION)
            .awaitFirstOrNull()
	}


    /**
     * Immediately revokes one or more user IDs for a fixed duration (default: 1 hour).
     *
     * After revocation:
     * - All sessions belonging to the user(s) are considered invalid, regardless of which token they use.
     * - The revocation is distributed across all application instances via Redis.
     *
     * Typical use cases:
     * - Administrative account suspension.
     * - Fraud or abuse mitigation.
     * - Emergency lockouts.
     *
     * @param ids One or more user identifiers to revoke.
     */
	suspend fun revokeUserId(vararg ids : String)
	{
        val ops = redisTemplate.opsForValue()

        for (id in ids) {
            ops.set("$PREFIX_USER::$id", "1", SESSION_REVOCATION_DURATION).awaitFirstOrNull()
        }
	}


    /**
     * Checks whether a given user session or authorization token is currently revoked.
     *
     * At least one of `userId` or `token` must be provided. Both may be checked together
     * to enforce combined revocation policies.
     *
     * Evaluation logic:
     * - If the `userId` is revoked → returns `true` (all sessions for that user are blocked).
     * - If the `token` is revoked → returns `true` (the specific session is blocked).
     * - If neither is revoked → returns `false`.
     *
     * @param userId User identifier to check (nullable).
     * @param token Authorization token to check (nullable).
     * @return `true` if the user or token has an active revocation entry, otherwise `false`.
     */
	suspend fun isSessionSuspended(
		userId : String?,
		token : String?
	) : Boolean
	{
		val keysToCheck = buildList {
			if (!userId.isNullOrBlank()) add("$PREFIX_USER::$userId")
			if (!token.isNullOrBlank()) add("$PREFIX_AUTH::$token")
		}.ifEmpty { return false }

		val values = redisTemplate.opsForValue()
            .multiGet(keysToCheck)
            .awaitFirstOrNull()

		return !values.isNullOrEmpty() && values.any { it != null }
	}


    /**
     * Constructs a unique Redis key for storing rate-limiting state.
     *
     * Key format:
     * - `IP` strategy:   `"rate::{method}::{uri}::{ipAddress}"`
     * - `USER` strategy: `"rate::{method}::{uri}::{userId}"`
     * - `ALL` strategy:  `"rate::{method}::{uri}"`
     *
     * Keys are scoped by HTTP method and URI to avoid collisions across endpoints.
     *
     * @param method HTTP method (GET, POST, etc.).
     * @param uri Request path.
     * @param userId User identifier (only used for USER strategy).
     * @param ipAddress Client IP address (only used for IP strategy).
     * @param strategy Rate limiting strategy that determines key format.
     * @return Redis key string.
     */
	private fun buildKeyForRateLimit(
		method : String,
		uri : String,
		userId : String?,
		ipAddress : String?,
		strategy : RateLimitStrategy
	) : String
	{
		return when (strategy)
		{
			RateLimitStrategy.IP -> "$PREFIX_RATE::${method}::${uri}::${ipAddress}"
			RateLimitStrategy.USER -> "$PREFIX_RATE::${method}::${uri}::${userId}"
			RateLimitStrategy.ALL -> "$PREFIX_RATE::${method}::${uri}"
		}
	}
}