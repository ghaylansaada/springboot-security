package io.ghaylan.springboot.security.annotations

import io.ghaylan.springboot.security.AuthDescriptor
import io.ghaylan.springboot.security.model.AuthScheme

/**
 * Declares that an endpoint requires authentication using one or more specified [AuthScheme]s.
 *
 * This annotation marks a controller method as **secured**, requiring incoming requests to be
 * authenticated using at least one of the specified schemes (e.g., bearer token, API key, HMAC).
 *
 * ## 🔧 Role & Permission Requirements
 * - This annotation alone does **not** specify roles or permissions.
 * - Projects must define **custom annotations** (e.g., `@RequiresRoles`, `@RequiresPermissions`) to declare
 *   required roles and fine-grained permissions.
 * - These project-specific annotations are interpreted by [AuthDescriptor], which resolves them
 *   via `resolveAuthorizationRequirements()`.
 *
 * ## 🚫 Startup Validation
 * - If [AuthScheme.BEARER] is present, the container will verify that at least one **role or permission**
 *   annotation is also present on the same method.
 * - If [AuthScheme.API_KEY], [AuthScheme.HMAC], or [AuthScheme.BASIC] is present, at least one
 *   role or permission annotation must be resolvable through [AuthDescriptor].
 * - If requirements are missing, startup will **fail fast** with a descriptive error message.
 *
 * ## ⚠️ Usage Guidelines
 * - Use together with project-specific role/permission annotations.
 * - At least one scheme must be specified.
 * - [AuthScheme.BEARER] requires both roles and/or permissions to be explicitly declared.
 *
 * ## ✅ Usage Examples
 *
 * ### Bearer token with explicit access control
 * ```kotlin
 * @AuthorizedEndpoint(schemes = [AuthScheme.BEARER])
 * @AccessControl(roles = [Role.ADMIN], permissions = [Permission.READ])
 * @GetMapping("/admin")
 * suspend fun getAdminData(): AdminData { ... }
 * ```
 *
 * ### API key with role-based access
 * ```kotlin
 * @AuthorizedEndpoint(schemes = [AuthScheme.API_KEY])
 * @RequiresPartnerRole
 * @GetMapping("/partner")
 * suspend fun getPartnerData(): PartnerData { ... }
 * ```
 *
 * ## 🔐 Supported Authentication Schemes
 * - [AuthScheme.BEARER] – JWT-based bearer tokens (requires roles and/or permissions)
 * - [AuthScheme.API_KEY] – API key-based authentication (requires roles/permissions)
 * - [AuthScheme.HMAC] – HMAC-signed requests (requires roles/permissions)
 * - [AuthScheme.BASIC] – HTTP Basic Authentication (requires roles/permissions)
 *
 * @param schemes One or more authentication schemes required to access the endpoint.
 *                Must not be empty.
 */
@MustBeDocumented
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class AuthorizedEndpoint(val schemes: Array<AuthScheme>)