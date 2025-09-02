package io.ghaylan.springboot.security.model

import io.ghaylan.springboot.security.model.role.RoleAccessPolicy
import io.ghaylan.springboot.security.model.token.TokenAccessPolicy
import java.time.Instant
import java.util.Locale

/**
 * Represents the standardized authentication context for a user within the security framework.
 *
 * This generic data structure encapsulates all relevant authentication and request-related information,
 * enabling consistent handling of security concerns across different projects and implementations.
 * Projects are expected to extend this class with concrete types tailored to their specific roles,
 * permissions, and user details.
 *
 * ---
 *
 * ### Key Components
 * - **User Information:** Identity, role, display name, and additional project-specific details.
 * - **Localization:** User's preferred locale for localized content delivery.
 * - **Request Metadata:** Includes HTTP headers, client IP, and user agent.
 * - **Timestamp:** The instant when authentication was performed.
 *
 * ---
 *
 * ### Generic Parameters
 * - `RoleT`: Enum representing user roles, must implement [RoleAccessPolicy].
 * - `PermissionT`: Enum representing user permissions.
 * - `UserT`: Custom user detail type for project-specific data.
 *
 * ---
 *
 * @property user Authenticated user details.
 * @property locale Preferred [Locale] for response localization.
 * @property header Extracted HTTP header information relevant to authentication.
 * @property ipAddress Client IP address.
 * @property userAgent Optional user agent string from the client.
 * @property datetime Timestamp when authentication was processed.
 */
open class GenericAuthentication<RoleT, PermissionT, TokenT, UserT: GenericAuthentication.User<String, String, RoleT, PermissionT>>(
    val user: UserT,
    val tokenType: TokenT,
    val locale: Locale,
    val header: HeaderInfo,
    val ipAddress: String,
    val userAgent: String?,
    val datetime: Instant
) where RoleT : Enum<RoleT>, RoleT : RoleAccessPolicy, PermissionT : Enum<PermissionT>, TokenT : Enum<TokenT>, TokenT : TokenAccessPolicy
{

    /**
     * Encapsulates the authenticated user’s identity and authorization role.
     *
     * Projects should implement their role enums to conform to [RoleAccessPolicy].
     *
     * @property id Unique identifier for the user.
     * @property name Optional user display name.
     * @property role User's assigned role for authorization checks.
     * @property permissions User's assigned permissions for authorization checks.
     */
    open class User<IdT, NameT, RoleT, PermissionT>(
        val id: IdT,
        val name: NameT?,
        val role: RoleT,
        val permissions: Set<PermissionT>,
    ) : HashMap<String, Any?>() where RoleT : Enum<RoleT>, RoleT : RoleAccessPolicy, PermissionT : Enum<PermissionT>


    /**
     * Contains HTTP header values relevant to authentication and request tracing.
     *
     * @property authScheme The authentication scheme used (e.g., Bearer, ApiKey).
     * @property authorization The raw `Authorization` header value.
     * @property secretCode Optional secret code provided via a custom header.
     * @property requestId Optional request ID for distributed tracing or logging.
     */
    data class HeaderInfo(
        val authScheme: AuthScheme?,
        val authorization: String?,
        val secretCode: String?,
        val requestId: String?
    ) : HashMap<String, Any?>()
}