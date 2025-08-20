package io.ghaylan.springboot.security.model.role

import io.ghaylan.springboot.security.filter.AuthenticationFilter

/**
 * Must be implemented by all role enums in projects using this security library.
 *
 * This interface enforces that every role in a project explicitly defines its access scope
 * using [RoleAccessScope]. By doing so, the framework can categorize roles as public,
 * internal, or secured, and apply the correct authentication and authorization strategies.
 *
 * ## Project Integration
 * - Each project must define its own `enum class` for roles (e.g., `MyRole`) that implements this interface.
 * - This contract enables the security engine to resolve the nature of a role at runtime,
 *   particularly within filters such as [AuthenticationFilter].
 * - The role's [scope] is used to route requests through the correct authentication logic
 *   (anonymous, internal service, or user token).
 *
 * ## Example
 * ```kotlin
 * enum class MyRole(override val scope: RoleAccessScope) : RoleAccessPolicy {
 *     PUBLIC_USER(RoleAccessScope.PUBLIC),
 *     INTERNAL_SERVICE(RoleAccessScope.INTERNAL),
 *     REGISTERED_USER(RoleAccessScope.SECURED)
 * }
 * ```
 *
 * ## Enforcement
 * The framework expects all roles used in authentication tokens to implement this interface.
 * If a role does not implement `RoleAccessPolicy`, the request will be rejected during authorization.
 */
interface RoleAccessPolicy
{
	/**
	 * Declares the access scope of the role.
	 *
	 * The scope is used internally by the security engine to determine which authentication
	 * flow should be applied when handling requests with this role.
	 */
	val scope : RoleAccessScope
}