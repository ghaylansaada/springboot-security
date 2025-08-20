# Spring Boot Reactive Security

A production-ready, **annotation-driven** security framework for Spring Boot **WebFlux** applications that eliminates boiler-plate configuration while enforcing strict authentication, authorization, and rate-limiting policies out-of-the-box.

## Overview

This library delivers a complete security solution for Spring Boot projects that facilitates security setup by minimizing configuration while enforcing robust authentication and authorization policies. It improves upon ad-hoc Spring Security configurations in several key ways:

- **Zero-config startup**: Automatically detects endpoints and builds security schemas at application start
- **Multi-scheme authentication**: Out-of-the-box support for Bearer (JWT), API Key, HMAC-SHA256 and HTTP Basic
- **Fail-fast validation**: Missing roles, extractors, or permissions cause application startup to fail with clear error messages  
- **Role & Permission enforcement**: Compile-time validation of your role model via the central `AuthDescriptor` class
- **Distributed rate-limiting**: Sliding-window algorithm backed by Redis with IP / USER / GLOBAL scopes
- **Reactive, non-blocking**: End-to-end coroutine-friendly implementation designed for WebFlux

Perfect for teams who need strong security guarantees without spending days wiring Spring Security configurations. The framework enforces security best practices through the `AuthDescriptor` contract - the main class that projects must implement to bridge their domain model to the security engine.

> **Note**: Currently, this framework is reactive-first and designed for **Spring WebFlux**. Spring WebMVC support is not available yet.

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
  - [Startup Process: Building Security Container](#startup-process-building-security-container)
  - [Startup Process: Role & Schema Validation](#startup-process-role--schema-validation) 
  - [Runtime Authentication Flow](#runtime-authentication-flow)
- [Getting Started](#getting-started)
- [Usage Examples](#usage-examples)
- [Built-in Authentication Extractors](#built-in-authentication-extractors)
- [Error Handling](#error-handling)
- [Extending the Framework](#extending-the-framework)
- [Performance Considerations](#performance-considerations)
- [Why Use This Framework?](#why-use-this-framework)

## Features

- **Endpoint scoping annotations**: `@PublicEndpoint`, `@InternalEndpoint`, `@AuthorizedEndpoint` with startup validation
- **AuthDescriptor contract**: Single abstract class bridges your domain roles/permissions to the security engine
- **Extractor architecture**: Pluggable authentication extractors with configurable user-source callbacks
- **Rate-limiting strategies**: `IP`, `USER`, `ALL` strategies with atomic Redis Lua script execution
- **Session / token revocation**: Instant user and token suspension with configurable TTL
- **Centralized error model**: `SecurityViolationException` carrying typed `HttpStatusCode` enums
- **Authentication injection**: Automatic injection of typed authentication objects into controller methods
- **Startup self-audit**: Validates role model, extractors, and endpoint annotations before application starts

## How It Works

The security framework operates through a series of steps that span from application startup to runtime request handling. The core principle is to perform all expensive validation and schema building at startup, then use cached components during request processing for optimal performance.

### Startup Process: Building Security Container

When the application starts:

1. **Endpoint Discovery**: `EndpointsFinder` scans all controller methods for security annotations (`@PublicEndpoint`, `@InternalEndpoint`, `@AuthorizedEndpoint`)
2. **Schema Generation**: For each endpoint, the framework creates a `SecuritySchema` containing:
   - Required authentication schemes (Bearer, API Key, HMAC, Basic)
   - Allowed roles and permissions resolved via `AuthDescriptor.resolveAuthorizationRequirements()`
   - Rate-limiting configuration
   - Access scope (PUBLIC, INTERNAL, SECURED)
3. **Extractor Registry**: All `AbstractAuthExtractor` beans are collected and indexed by supported scheme
4. **SecurityContainer Assembly**: Bundles schemas, extractors, `AuthDescriptor`, and optional `RateLimitManager`

### Startup Process: Role & Schema Validation  

The `AuthDescriptor` runs a comprehensive self-audit to ensure your **Role** enum follows required constraints:

- **Exactly one** `RoleAccessScope.INTERNAL` role for system communication
- **Exactly one** `RoleAccessScope.PUBLIC` role for anonymous access  
- **At least one** `RoleAccessScope.SECURED` role for authenticated users

Additionally, the framework validates that:
- All `@AuthorizedEndpoint` methods have corresponding role/permission annotations
- All required extractors are present as Spring beans
- Custom authorization annotations are properly resolved by `AuthDescriptor`

Missing or misconfigured elements cause application startup to **fail fast** with descriptive error messages, preventing unsafe deployments.

### Runtime Authentication Flow

When a request arrives:

1. **AuthenticationFilter** (WebFilter) intercepts the request
2. **Schema Lookup**: Finds endpoint-specific security requirements from cached schemas
3. **Early Rate-Limiting**: Applies IP/GLOBAL limits before expensive authentication
4. **Body Caching**: Conditionally caches request body for HMAC signature validation
5. **Extractor Chain**: Routes to appropriate extractor based on Authorization header scheme
6. **User Resolution**: Extractor calls your user-source callback to resolve user data
7. **Authentication Mapping**: `AuthDescriptor.mapGenericAuth()` converts to your domain type
8. **Authorization Checks**: Validates user roles and permissions against endpoint requirements
9. **Late Rate-Limiting**: Applies USER-specific quotas after authentication
10. **Context Injection**: Stores authentication in ReactiveSecurityContextHolder for controllers
11. **Argument Resolution**: `AuthenticationArgumentResolver` injects typed auth into controller methods

This approach ensures authentication is performed with minimal overhead, as all expensive operations were moved to the application startup phase.

## Getting Started

### Add Dependency

#### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.ghaylan.springboot:security:1.0.0")
}
```

#### Maven

```xml
<dependency>
    <groupId>io.ghaylan.springboot</groupId>
    <artifactId>security</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Enable Auto-configuration

The framework auto-configures itself when added to a Spring Boot application. Just add the dependency and implement the required components:

1. Implement `AuthDescriptor` abstract class
2. Register authentication extractors as Spring beans  
3. Define custom authorization annotations (if using `@AuthorizedEndpoint`)

No additional Spring Security configuration is required - the framework handles WebFilter registration automatically.

## Usage Examples

### 1. Implement AuthDescriptor (Required)

The `AuthDescriptor` is the central bridge between your domain model and the security framework:

```kotlin
// Define your domain enums
enum class Role(override val scope: RoleAccessScope) : RoleAccessPolicy {
    GUEST(RoleAccessScope.PUBLIC),
    SYSTEM(RoleAccessScope.INTERNAL), 
    USER(RoleAccessScope.SECURED),
    ADMIN(RoleAccessScope.SECURED)
}

enum class Permission { READ, WRITE, DELETE }

// Define custom authorization annotation
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class AccessControl(
    val roles: Array<Role> = [],
    val permissions: Array<Permission> = []
)

// Implement AuthDescriptor
@Component
class MyAuthDescriptor : AuthDescriptor<MyAuth, Role, Permission>() {
    override val roleClass = Role::class.java
    override val permissionClass = Permission::class.java

    override fun mapGenericAuth(genericAuth: GenericAuthentication<*, *, *>): MyAuth {
        // Convert framework authentication to your domain type
        return MyAuth(
            userId = genericAuth.user.id,
            role = genericAuth.user.role as Role,
            permissions = genericAuth.user.permissions as Set<Permission>,
            // ... other domain-specific fields
        )
    }

    override fun resolveAuthorizationRequirements(annotations: Array<Annotation>): Pair<Set<Permission>, Set<Role>> {
        // Extract roles and permissions from your custom annotations
        val accessControl = annotations.filterIsInstance<AccessControl>().firstOrNull()
            ?: return emptySet<Permission>() to emptySet<Role>()
            
        return accessControl.permissions.toSet() to accessControl.roles.toSet()
    }
}
```

### 2. Register Authentication Extractors

Each extractor requires a user-source callback to resolve authentication data:

```kotlin
@Configuration
class SecurityConfig {

    @Bean
    fun bearerAuthExtractor(
        userJwtReader: UserJwtReader,
        systemJwtManager: SystemJwtManager<Role>
    ) = BearerAuthExtractor(userJwtReader, systemJwtManager)

    @Bean 
    fun apiKeyExtractor(apiKeyManager: ApiKeyManager, userRepository: UserRepository) =
        ApiKeyAuthExtractor(apiKeyManager) { apiKey ->
            // Resolve user from your data source
            userRepository.findByApiKey(apiKey)?.let { user ->
                RawExtractedAuth(
                    id = user.id,
                    role = user.role.name,
                    name = user.name,
                    permissions = user.permissions.map { it.name },
                    credentials = user.secretKey
                )
            }
        }

    @Bean
    fun hmacAuthExtractor(hmacManager: HmacManager, partnerService: PartnerService) =
        HmacAuthExtractor(hmacManager) { apiKey ->
            // Resolve partner user from your service
            partnerService.findByApiKey(apiKey)?.let { partner ->
                RawExtractedAuth(
                    id = partner.id,
                    role = Role.USER.name,
                    name = partner.companyName,
                    permissions = partner.permissions.map { it.name },
                    credentials = partner.hmacSecret
                )
            }
        }

    @Bean
    fun basicAuthExtractor(userService: UserService) =
        BasicAuthExtractor { username, password ->
            // Validate credentials against your data source
            userService.authenticate(username, password)?.let { user ->
                RawExtractedAuth(
                    id = user.id,
                    role = user.role.name, 
                    name = user.name,
                    permissions = user.permissions.map { it.name },
                    credentials = null
                )
            }
        }
}
```

### 3. Secure Endpoints with Annotations

```kotlin
@RestController
@RequestMapping("/api")
class UserController {

    // Public endpoint - no authentication required
    @PublicEndpoint
    @GetMapping("/docs")
    suspend fun documentation(): String = "API Documentation"

    // Secured endpoint with custom authorization
    @AuthorizedEndpoint(schemes = [AuthScheme.BEARER])
    @AccessControl(roles = [Role.USER], permissions = [Permission.READ])
    @GetMapping("/profile")
    suspend fun getProfile(auth: MyAuth): ProfileDto {
        // 'auth' is automatically injected as your domain type
        return profileService.getProfile(auth.userId)
    }

    // Admin-only endpoint with multiple schemes
    @AuthorizedEndpoint(schemes = [AuthScheme.BEARER, AuthScheme.API_KEY])
    @AccessControl(roles = [Role.ADMIN], permissions = [Permission.WRITE])
    @PostMapping("/admin/users")
    suspend fun createUser(@RequestBody user: CreateUserDto, auth: MyAuth): UserDto {
        return userService.createUser(user, auth.userId)
    }

    // Internal system endpoint
    @InternalEndpoint
    @PostMapping("/internal/sync")
    suspend fun syncData(): SyncResult = syncService.performSync()
}
```

### 4. Optional: Enable Rate Limiting

```kotlin
@Bean
fun rateLimitManager(redisTemplate: ReactiveStringRedisTemplate) = RateLimitManager(redisTemplate)
```

## Built-in Authentication Extractors

The framework provides four production-ready authentication extractors, each designed for specific use cases:

### Bearer Token Extractor

Handles JWT token authentication for both user and system access:

| Feature | Description |
|---------|-------------|
| **Header Format** | `Authorization: Bearer <jwt-token>` |
| **Use Cases** | User authentication, internal service communication |
| **Security** | JWT signature validation, expiration checking, audience validation |
| **Body Required** | No |

```kotlin
@Bean
fun bearerAuthExtractor(userJwtReader: UserJwtReader, systemJwtManager: SystemJwtManager<Role>) =
    BearerAuthExtractor(userJwtReader, systemJwtManager)
```

### API Key Extractor  

Designed for service-to-service communication with encrypted, long-lived credentials:

| Feature | Description |
|---------|-------------|
| **Header Format** | `Authorization: ApiKey <encrypted-api-key>` |
| **Use Cases** | Partner APIs, service authentication, external integrations |
| **Security** | AES-GCM encryption, expiration validation, prefix checking |
| **Body Required** | No |

```kotlin
@Bean
fun apiKeyExtractor(apiKeyManager: ApiKeyManager, userRepo: UserRepository) =
    ApiKeyAuthExtractor(apiKeyManager) { apiKey ->
        // Your user resolution logic
        userRepo.findByApiKey(apiKey)?.toRawAuth()
    }
```

### HMAC Signature Extractor

Provides the highest security level with request signing and replay protection:

| Feature | Description |
|---------|-------------|  
| **Header Format** | `Authorization: HMAC apiKey=...,signature=...,timestamp=...` |
| **Use Cases** | High-security APIs, financial transactions, sensitive operations |
| **Security** | HMAC-SHA256 signing, body integrity, timestamp validation, replay protection |
| **Body Required** | Yes (included in signature) |

```kotlin
@Bean  
fun hmacExtractor(hmacManager: HmacManager, partnerService: PartnerService) =
    HmacAuthExtractor(hmacManager) { apiKey ->
        // Resolve partner with HMAC secret
        partnerService.findByApiKey(apiKey)?.toRawAuth()
    }
```

### Basic Auth Extractor

Traditional username/password authentication for legacy system integration:

| Feature | Description |
|---------|-------------|
| **Header Format** | `Authorization: Basic <base64(username:password)>` |
| **Use Cases** | Legacy system integration, simple authentication scenarios |
| **Security** | Base64 decoding, credential validation (requires HTTPS) |
| **Body Required** | No |

```kotlin
@Bean
fun basicAuthExtractor(userService: UserService) =
    BasicAuthExtractor { username, password ->
        // Validate credentials
        userService.authenticate(username, password)?.toRawAuth()
    }
```

### Extractor Architecture

All extractors extend `AbstractAuthExtractor` and follow a common pattern:

1. **Credential Extraction**: Parse the Authorization header according to scheme format
2. **User Resolution**: Call your provided callback to resolve user data from your data source  
3. **Validation**: Perform scheme-specific validation (signatures, expiration, format)
4. **Raw Authentication**: Return `RawExtractedAuth` with user identity and credentials
5. **Domain Mapping**: Framework calls `AuthDescriptor.mapGenericAuth()` to convert to your domain type

The user resolution callbacks make extractors flexible - you can integrate with any data source (database, external API, cache, etc.) using your existing repositories and services.

## Error Handling

### Security Exception Model

All security failures throw `SecurityViolationException` wrapping a typed `HttpStatusCode`:

```kotlin
enum class HttpStatusCode(val status: HttpStatus, val message: String) {
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Authentication failed: invalid or missing credentials"),
    FORBIDDEN(HttpStatus.FORBIDDEN, "Access denied: insufficient roles or permissions"),
    EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "Authentication failed: session has expired"),
    TOO_MANY_REQUESTS(HttpStatus.TOO_MANY_REQUESTS, "Too many requests: rate limit exceeded"),
    NOT_AVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "Service temporarily unavailable")
}
```

### Exception Handling

Define a global exception handler to convert security exceptions into consistent JSON responses:

```kotlin
@RestControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(SecurityViolationException::class)
    fun handleSecurityViolation(ex: SecurityViolationException): ResponseEntity<ErrorResponse> {
        val errorResponse = ErrorResponse(
            status = ex.code.status.value(),
            message = ex.message,
            timestamp = Instant.now()
        )
        
        return ResponseEntity.status(ex.code.status).body(errorResponse)
    }
}

data class ErrorResponse(
    val status: Int,
    val message: String?,
    val timestamp: Instant
)
```

### Startup Validation Errors

The framework performs extensive validation at startup and throws descriptive exceptions for misconfigurations:

- **Missing AuthDescriptor**: "No AuthDescriptor bean found"
- **Invalid Role Model**: "Exactly one INTERNAL role is required, but found 2"  
- **Missing Extractors**: "No extractor found for scheme BEARER"
- **Misconfigured Endpoints**: "No roles or permissions resolved from AuthDescriptor"

These fail-fast behaviors ensure security misconfigurations are caught before deployment.

## Extending the Framework

### Creating Custom Authentication Extractors

1. **Extend AbstractAuthExtractor**:

```kotlin
class CustomAuthExtractor(
    private val customValidator: CustomValidator,
    private val userResolver: suspend (token: String) -> RawExtractedAuth?
) : AbstractAuthExtractor(AuthScheme.CUSTOM) {

    override suspend fun extractAuthentication(
        request: ServerHttpRequest,
        credentials: String, 
        isInternalRequest: Boolean,
        rawRequestBody: String?
    ): RawExtractedAuth {
        // Custom validation logic
        val isValid = customValidator.validate(credentials)
        if (!isValid) {
            throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED)
        }
        
        // Resolve user from your data source
        return userResolver(credentials) 
            ?: throw SecurityViolationException(HttpStatusCode.UNAUTHORIZED)
    }
}
```

2. **Register as Spring Bean**:

```kotlin
@Bean
fun customAuthExtractor(validator: CustomValidator, userService: UserService) =
    CustomAuthExtractor(validator) { token ->
        userService.findByToken(token)?.toRawAuth()
    }
```

### Custom Rate Limiting Backend

Replace the default Redis-based rate limiter with your own implementation:

```kotlin
@Bean
@Primary
fun customRateLimitManager(): RateLimitManager {
    return MyCustomRateLimitManager() // Your implementation
}
```

### Advanced Authorization Logic

Override `resolveAuthorizationRequirements()` in `AuthDescriptor` to handle complex annotation patterns:

```kotlin
override fun resolveAuthorizationRequirements(annotations: Array<Annotation>): Pair<Set<Permission>, Set<Role>> {
    val permissions = mutableSetOf<Permission>()
    val roles = mutableSetOf<Role>()
    
    // Handle multiple custom annotations
    annotations.filterIsInstance<RequiresPermission>().forEach {
        permissions.addAll(it.permissions)
    }
    
    annotations.filterIsInstance<RequiresRole>().forEach {
        roles.addAll(it.roles)
    }
    
    // Complex business logic for role inheritance, etc.
    
    return permissions to roles
}
```

## Performance Considerations

This security framework is designed for high-performance reactive applications:

### Startup Optimizations

- **Schema Pre-computation**: All endpoint security schemas built once at startup
- **Extractor Caching**: Authentication extractors registered and indexed by scheme
- **Role Validation**: Domain model validated once to prevent runtime errors
- **Zero Reflection**: Field access and constraint resolution moved to startup phase

### Runtime Optimizations

- **Early Rejection**: IP/global rate limits checked before expensive authentication
- **Single Body Read**: Request payload cached once for both HMAC validation and business logic  
- **Constant-Time Comparisons**: HMAC signatures compared using secure algorithms
- **Coroutine-Friendly**: Fully non-blocking implementation with suspend functions
- **Context Reuse**: Authentication stored in Reactor context for downstream access

### Memory and CPU Efficiency

- **Cached Schemas**: Validation paths precomputed, eliminating annotation scanning overhead
- **Optimized Lookups**: Schema retrieval uses efficient URI/method matching
- **Minimal Allocations**: Reduced object creation during request processing
- **Atomic Operations**: Redis Lua scripts ensure consistency without multiple round-trips

### Performance Benefits

- **Lower Latency**: Faster authentication compared to traditional Spring Security chains
- **Higher Throughput**: Can handle more concurrent requests per second
- **Predictable Performance**: Consistent response times due to precomputed schemas  
- **Reduced Memory Usage**: Less garbage collection pressure from cached components

## Why Use This Framework?

### Advantages over Standard Spring Security

| Feature | This Framework | Standard Spring Security |
|---------|---------------|-------------------------|
| **Setup Complexity** | Auto-configures with AuthDescriptor | Manual SecurityFilterChain configuration |
| **Multi-Scheme Auth** | Bearer, API Key, HMAC, Basic out-of-box | Custom filter implementations required |
| **Rate Limiting** | Built-in Redis sliding window | External library integration needed |
| **Startup Safety** | Fails fast on misconfigurations | Silent failures possible at runtime |
| **WebFlux Support** | Native reactive with coroutines | Adaptation layer with blocking elements |
| **Schema Validation** | Compile-time endpoint validation | Runtime discovery of security issues |
| **Performance** | Precomputed schemas, zero reflection | Reflection-heavy chain processing |
| **User Injection** | Automatic domain-type injection | Manual SecurityContext retrieval |

### When to Use This Framework

- **Reactive Applications**: When using Spring WebFlux with or without coroutines
- **Multi-Scheme APIs**: When you need Bearer, API Key, HMAC authentication  
- **High-Performance Systems**: When authentication speed and throughput matter
- **API-First Designs**: For consistent, structured security across endpoints
- **Team Productivity**: When you want security setup without Spring Security complexity
- **Fail-Fast Requirements**: When security misconfigurations must be caught at startup

### Use Cases

- **Microservices**: Internal communication with JWT + external partner APIs with HMAC
- **High-Throughput APIs**: E-commerce, financial services requiring fast authentication
- **Multi-Tenant SaaS**: Different authentication schemes for different customer tiers
- **Partner Integrations**: API keys for partners, HMAC for high-security transactions
- **Mobile Backends**: JWT tokens for mobile apps with rate limiting per user
- **Internal Tooling**: System tokens for automated processes and monitoring

## License

### MIT License

Copyright (c) 2025 Ghaylan Saada

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.