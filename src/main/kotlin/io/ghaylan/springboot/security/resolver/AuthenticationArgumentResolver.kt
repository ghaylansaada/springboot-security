package io.ghaylan.springboot.security.resolver

import io.ghaylan.springboot.security.AuthDescriptor
import io.ghaylan.springboot.security.exception.HttpStatusCode
import io.ghaylan.springboot.security.exception.SecurityViolationException
import io.ghaylan.springboot.security.model.GenericAuthentication
import org.springframework.core.MethodParameter
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.web.reactive.BindingContext
import org.springframework.web.reactive.result.method.HandlerMethodArgumentResolver
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Argument resolver for injecting project-specific authentication objects into WebFlux controller methods.
 *
 * This resolver allows controller methods to declare strongly-typed authentication parameters,
 * automatically mapping from the framework's [GenericAuthentication] to your project's custom
 * authentication type.
 *
 * ---
 *
 * ### Purpose
 * Spring Security stores authentication in a generic [GenericAuthentication] object.
 * Projects usually extend this class to include domain-specific details such as user IDs,
 * roles, and permissions.
 *
 * This resolver automates the conversion, so you can directly inject your custom
 * authentication type into controller method parameters without manual casting.
 *
 * ---
 *
 * ### How It Works
 * 1. **Retrieve** the current authentication from [ReactiveSecurityContextHolder].
 * 2. **Validate** that an authenticated user exists; otherwise, throw [SecurityViolationException].
 * 3. **Map** the generic authentication into your project-specific type via [AuthDescriptor.mapGenericAuth].
 * 4. **Inject** the mapped object as the method parameter.
 *
 * ---
 *
 * ### Usage Example
 * ```kotlin
 * @GetMapping("/profile")
 * suspend fun getProfile(auth: MyProjectAuthentication): UserProfile {
 *     // 'auth' is already your concrete authentication type
 *     return userService.loadUserProfile(auth.user.id)
 * }
 * ```
 *
 * In this example, `MyProjectAuthentication` is your own class extending [GenericAuthentication].
 *
 * ---
 *
 * ### Notes
 * - Supports **only your project-specific authentication types**, not [GenericAuthentication] directly.
 * - Requires an [AuthDescriptor] implementation that can map the generic authentication to your type.
 * - Throws [SecurityViolationException] if no authentication is present in the context.
 * - Integrates seamlessly with WebFlux's argument resolution mechanism.
 *
 * ---
 *
 * @param authDescriptor Responsible for mapping generic authentication to project-specific authentication.
 */
open class AuthenticationArgumentResolver(
    private val authDescriptor: AuthDescriptor<*, *, *>
) : HandlerMethodArgumentResolver
{

    /**
     * Determines whether the resolver supports the given method parameter.
     *
     * Returns `true` if the parameter type is a subclass of [GenericAuthentication].
     * Override if your project has stricter requirements.
     */
    override fun supportsParameter(parameter: MethodParameter): Boolean
    {
        return GenericAuthentication::class.java.isAssignableFrom(parameter.parameterType)
    }


    /**
     * Resolves the method argument by:
     * - Retrieving the generic authentication from the security context
     * - Mapping it to the project-specific authentication type
     *
     * Throws [SecurityViolationException] if no authenticated user is found.
     */
    override fun resolveArgument(
        parameter: MethodParameter,
        bindingContext: BindingContext,
        exchange: ServerWebExchange
    ): Mono<Any>
    {
        return ReactiveSecurityContextHolder.getContext()
            .map { ctx -> ctx.authentication.details }
            .cast(GenericAuthentication::class.java)
            .map { genericAuth -> authDescriptor.mapGenericAuth(genericAuth)!! }
            .switchIfEmpty(Mono.error(SecurityViolationException(HttpStatusCode.UNAUTHORIZED, "Authentication failed: no authenticated user found")))
    }
}