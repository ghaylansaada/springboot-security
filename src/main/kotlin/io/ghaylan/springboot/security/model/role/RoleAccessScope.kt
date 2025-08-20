package io.ghaylan.springboot.security.model.role

/**
 * Defines the access scope categories for roles in the security model.
 *
 * This enum enables the security framework to determine the required authentication behavior
 * based on the scope associated with a user's role (via [RoleAccessPolicy]).
 *
 * ## Constraints
 * - **Only one `PUBLIC` role** must exist per project — it represents anonymous access.
 * - **Only one `INTERNAL` role** must exist — used strictly for internal service communication.
 * - **Multiple `SECURED` roles** can be defined to represent various authenticated user roles.
 *
 * These constraints ensure consistent routing of requests through the proper authentication flows.
 */
enum class RoleAccessScope
{
	/**
	 * Role used for public endpoints where no authentication is required.
	 *
	 * Typically applied to anonymous users accessing open APIs, static content, or
	 * non-sensitive resources. Associated with `@PublicEndpoint`.
	 *
	 * **Only one role in your project should use this scope.**
	 */
	PUBLIC,

	/**
	 * Role used for internal endpoints restricted to trusted services.
	 *
	 * Reserved for system-to-system communication (e.g., between microservices).
	 * Requires internal credentials or service-issued tokens. Associated with `@InternalEndpoint`.
	 *
	 * **Only one role in your project should use this scope.**
	 */
	INTERNAL,

	/**
	 * Role used for secured endpoints requiring authenticated users.
	 *
	 * Requires the client to provide a valid token (e.g., JWT or API Key). Associated with `@AuthorizedEndpoint`.
	 *
	 * **Projects can define multiple roles with this scope to differentiate user permissions.**
	 */
	SECURED
}