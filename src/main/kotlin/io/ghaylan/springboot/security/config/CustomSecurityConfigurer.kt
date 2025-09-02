package io.ghaylan.springboot.security.config

import io.ghaylan.springboot.security.AuthDescriptor
import io.ghaylan.springboot.security.exception.SecurityViolationException
import io.ghaylan.springboot.security.resolver.AuthenticationArgumentResolver
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.web.reactive.config.WebFluxConfigurer
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer

/**
 * Auto-configuration for integrating custom authentication argument resolution into Spring WebFlux.
 *
 * This configuration automatically registers the [AuthenticationArgumentResolver] with WebFlux,
 * enabling controllers to declare project-specific authentication parameters without manual setup.
 *
 * ## Auto-Configuration Features
 * - **Conditional Activation**: Only activates when [AuthDescriptor] bean is present in context
 * - **Zero Configuration**: Works automatically once [AuthDescriptor] is implemented
 * - **Seamless Integration**: Registers with WebFlux's argument resolution pipeline
 *
 * ## How It Works
 * 1. Detects [AuthDescriptor] bean in application context
 * 2. Registers [AuthenticationArgumentResolver] with the detected descriptor
 * 3. Enables controllers to inject custom authentication types as method parameters
 * 4. Handles type mapping from generic authentication to project-specific types
 *
 * ## Configuration Behavior
 * The `@ConditionalOnBean(AuthDescriptor::class)` ensures this auto-configuration only activates
 * when a custom authentication descriptor exists, preventing unnecessary registration in projects
 * using only generic authentication.
 *
 * ## Benefits
 * - **Type Safety**: Strong typing for authentication objects in controllers
 * - **Clean Code**: No manual security context retrieval or casting required
 * - **IDE Support**: Full intellisense and compile-time validation
 * - **Consistent Error Handling**: Automatic [SecurityViolationException] on authentication failures
 *
 * @param authDescriptor Authentication descriptor for mapping generic to project-specific types
 */
@AutoConfiguration
@ConditionalOnBean(AuthDescriptor::class)
open class CustomSecurityConfigurer(
    private val authDescriptor : AuthDescriptor<*,*,*,*>
) : WebFluxConfigurer
{

    /**
     * Configures WebFlux argument resolvers by registering the custom authentication argument resolver.
     *
     * This method is called during WebFlux initialization to register custom argument resolvers.
     * The [AuthenticationArgumentResolver] is added to enable automatic injection of project-specific
     * authentication objects into controller method parameters.
     *
     * @param configurer The argument resolver configurer provided by WebFlux
     */
    override fun configureArgumentResolvers(configurer: ArgumentResolverConfigurer)
    {
        configurer.addCustomResolver(AuthenticationArgumentResolver(authDescriptor))
    }
}