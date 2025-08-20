package io.ghaylan.springboot.security

import io.ghaylan.springboot.security.model.GenericAuthentication
import io.ghaylan.springboot.security.model.role.RoleAccessPolicy
import io.ghaylan.springboot.security.model.role.RoleAccessScope
import io.ghaylan.springboot.security.resolver.AuthenticationArgumentResolver

/**
 * Core contract for integrating project-specific authentication and authorization logic.
 *
 * `AuthDescriptor` defines the bridge between your application's security model and the framework.
 * Every project using this security library must extend this abstract class and register it as a Spring bean.
 *
 * It enables you to define:
 * - Your custom authentication type ([AuthT])
 * - Your role enum ([RoleT]) with scoped access rules
 * - Your Permission enum ([PermissionT])
 *
 * The framework uses this descriptor to handle:
 * - Request authentication
 * - Controller-level authorization enforcement
 * - Role policy validation
 * - Runtime injection of authenticated user information
 *
 * ---
 *
 * ## Key Responsibilities
 * - **Authentication Conversion:** Converts parsed authentication into your typed [AuthT] using [mapGenericAuth], typically from JWTs or API keys.
 * - **Authorization Resolution:** Extracts security config (allowed roles & permissions) from annotations on methods marked with `@AuthorizedEndpoint`, using [resolveAuthorizationRequirements].
 * - **Role Model Validation:** On initialization, validates that your role strictly follow required scope ([RoleAccessScope]).
 *
 * ---
 *
 * ## Role Configuration Rules
 * Your [RoleT] enum **must**:
 * - Define **exactly one** role with `RoleAccessScope.INTERNAL`
 * - Define **exactly one** role with `RoleAccessScope.PUBLIC`
 * - Define **at least one** role with `RoleAccessScope.SECURED`
 *
 * These constraints ensure consistent interpretation of roles across public, secured, and internal endpoints.
 *
 * ---
 *
 * ## Framework Integration
 * The security framework automatically uses your implementation to:
 * - Inject typed authentication parameters into controller methods (via [AuthenticationArgumentResolver])
 * - Validate authorization configuration at startup
 * - Reject misconfigured endpoints or access policies during boot
 *
 * You must expose your implementation as a Spring bean:
 *
 * ```kotlin
 * @Bean
 * fun authDescriptor(): MyAuthDescriptor = MyAuthDescriptor()
 * ```
 *
 * ---
 *
 * @param AuthT The project's concrete authentication class extending [GenericAuthentication]
 * @param RoleT The enum type representing user roles, implementing [RoleAccessPolicy]
 * @param PermissionT The enum type representing permissions.
 */
abstract class AuthDescriptor<AuthT, RoleT, PermissionT> where RoleT : Enum<RoleT>, RoleT : RoleAccessPolicy, PermissionT : Enum<PermissionT>
{
    /** Role enum class declared by the project (used for validation and introspection). */
    abstract val roleClass: Class<RoleT>

    /** Permission enum class declared by the project (used for validation and introspection). */
    abstract val permissionClass: Class<PermissionT>

    /** All role enum constants declared in the project. */
    val allRoles: Array<RoleT> = roleClass.enumConstants
        ?: error("Role enum constants are null for ${roleClass.simpleName}")

    /** All permission enum constants declared in the project. */
    val allPermissions: Array<PermissionT> = permissionClass.enumConstants
        ?: error("Permission enum constants are null for ${permissionClass.simpleName}")


    init
    {
        validateRoleConfiguration()
    }


    /**
     * Converts a generic [GenericAuthentication] object to a project-specific authentication type.
     *
     * This function is invoked internally by [AuthenticationArgumentResolver] when resolving
     * controller method arguments of type [AuthT]. It transforms the raw parsed authentication
     * — including role, permissions, and user details — into the application's custom authentication model.
     *
     * ---
     *
     * ## Framework Integration
     * When a controller method declares a parameter of your custom authentication type (e.g., `MyAuth`),
     * the framework uses [AuthenticationArgumentResolver], which calls this method to convert the
     * parsed authentication into a typed object injected into the method.
     *
     * ---
     *
     * ## Example Use Case
     * ```kotlin
     * @GetMapping("/me")
     * suspend fun profile(auth: MyAuth): ProfileDto { ... }
     * ```
     * In this case, the framework will:
     * 1. Parse the JWT or API key from the request
     * 2. Create a [GenericAuthentication] object
     * 3. Call `mapGenericAuth(...)` to transform it into `MyAuth`
     *
     * @param genericAuth The raw authentication object parsed from the request
     * @return A fully typed authentication object specific to your application ([AuthT])
     */
    abstract fun mapGenericAuth(genericAuth: GenericAuthentication<*, *, *>): AuthT


    /**
     * Resolves the security configuration required for accessing a protected endpoint.
     *
     * This method is invoked during application startup to extract the allowed roles and permissions
     * from method-level annotations. It only applies to controller methods explicitly marked with
     * `@AuthorizedEndpoint`.
     *
     * ---
     *
     * ## Framework Behavior
     * During startup, the framework scans all controller methods. When it finds a method annotated
     * with `@AuthorizedEndpoint`, it expects:
     * - A roles annotation specifying which roles are allowed to access the method
     *   or/and
     * - A permissions annotation specifying which permissions are allowed to access the method
     *
     * Your implementation of this method is responsible for extracting that role & permission configuration
     * from the annotations array. If any required annotations are missing or misconfigured,
     * application startup will fail with a clear error.
     *
     * ---
     *
     * @param annotations The array of method-level annotations present on the controller endpoint
     * @return A [Pair] of the allowed roles & permissions.
     */
    abstract fun resolveAuthorizationRequirements(annotations: Array<Annotation>): Pair<Set<PermissionT>, Set<RoleT>>


    /**
     * Validates that the project's role enum defines a compliant access model.
     *
     * This method is automatically invoked on instantiation and enforces:
     * - Exactly **one** role with [RoleAccessScope.INTERNAL]
     * - Exactly **one** role with [RoleAccessScope.PUBLIC]
     * - At least **one** role with [RoleAccessScope.SECURED]
     *
     * ---
     *
     * These constraints ensure that the application has a clear and reliable access control model.
     * If they are not met, application startup will fail with a detailed exception.
     *
     * @throws IllegalArgumentException If the declared role scopes violate the access model
     */
    private fun validateRoleConfiguration()
    {
        val internalRoles = allRoles.count { it.scope == RoleAccessScope.INTERNAL }
        require(internalRoles == 1) {
            "Exactly one INTERNAL role is required, but found $internalRoles in ${roleClass.simpleName}"
        }

        val publicRoles = allRoles.count { it.scope == RoleAccessScope.PUBLIC }
        require(publicRoles == 1) {
            "Exactly one PUBLIC role is required, but found $publicRoles in ${roleClass.simpleName}"
        }

        val securedRoles = allRoles.count { it.scope == RoleAccessScope.SECURED }
        require(securedRoles >= 1) {
            "At least one SECURED role is required, but found $securedRoles in ${roleClass.simpleName}"
        }
    }
}