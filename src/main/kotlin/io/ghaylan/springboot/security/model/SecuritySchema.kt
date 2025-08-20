package io.ghaylan.springboot.security.model

import io.ghaylan.springboot.security.SecurityContainer
import io.ghaylan.springboot.security.filter.AuthenticationFilter
import io.ghaylan.springboot.security.ratelimit.RateLimited
import io.ghaylan.springboot.security.model.role.RoleAccessPolicy
import io.ghaylan.springboot.security.model.role.RoleAccessScope
import org.springframework.http.HttpMethod

/**
 * Represents the security configuration for a specific endpoint, defining authentication and authorization requirements.
 *
 * This data class encapsulates all security-related metadata for an endpoint, including authentication schemes,
 * authorization roles, access scope, permissions, and rate limiting policies. Used by the security
 * framework to enforce endpoint-specific security policies during request processing.
 *
 * ## Purpose
 * - **Endpoint Security Definition**: Defines comprehensive security requirements per endpoint
 * - **Authentication Configuration**: Specifies allowed authentication schemes
 * - **Authorization Rules**: Defines required roles and access scope for endpoint access
 * - **Authorization permissions**: Defines required permissions for endpoint access
 * - **Rate Limiting**: Configures request throttling and abuse prevention policies
 * - **Framework Integration**: Used by [AuthenticationFilter] and [SecurityContainer] for enforcement
 *
 * ## Security Enforcement
 * The [AuthenticationFilter] uses this schema to:
 * 1. Validate authentication scheme compatibility
 * 2. Enforce role-based authorization requirements
 * 3. Check permissions restrictions
 * 4. Apply rate limiting policies
 * 5. Determine access scope (PUBLIC/INTERNAL/SECURED)
 *
 * @param RoleT Role enumeration implementing [RoleAccessPolicy] for authorization decisions
 * @param PermissionT Permission type enumeration.
 *
 * @property method HTTP method (GET, POST, PUT, DELETE, etc.) for endpoint matching
 * @property uri URI pattern for endpoint identification, supports path variables and wildcards
 * @property authSchemes List of supported authentication schemes (Bearer, Basic, HMAC, ApiKey)
 * @property roles List of roles authorized to access this endpoint
 * @property permissions Required permissions for authentication, null if no specific type required
 * @property accessScope Access scope determining authentication level (PUBLIC/INTERNAL/SECURED)
 * @property rateLimit Rate limiting configuration, null if no rate limiting applied
 */
data class SecuritySchema<RoleT, PermissionT>(
    val method : HttpMethod,
    val uri : String,
    val authSchemes : List<AuthScheme>,
    val roles : Set<RoleT>,
    val permissions : Set<PermissionT>,
    val accessScope : RoleAccessScope,
    val rateLimit : RateLimited?,
) where RoleT: Enum<RoleT>, RoleT : RoleAccessPolicy, PermissionT: Enum<PermissionT>