package io.ghaylan.springboot.security.annotations

/**
 * Marks an endpoint as **internal-only**, intended strictly for service-to-service communication
 * within a trusted backend infrastructure.
 *
 * This annotation designates that the annotated controller method should only be accessible by
 * other internal services, typically within the same private network or trusted environment.
 * It is not intended for use by clients, browsers, or external-facing systems.
 *
 * ## 🔐 Security Considerations
 * To ensure strict internal access, the following protections must be enforced:
 *
 * - **Network Isolation**: Expose only through private networks (e.g. VPC, internal subnets, or service mesh).
 * - **Authentication**: Require signed internal tokens or mutual TLS for identity verification.
 * - **Access Control**: Validate that the calling service is authorized to invoke the endpoint.
 *
 * ## ✅ Valid Use Cases
 * - Internal API communication in microservices architectures
 * - Service coordination or orchestration across backend systems
 * - Internal data exchange between trusted backend components
 *
 * ## ❌ External Use Prohibited
 * Never expose endpoints annotated with `@InternalEndpoint` to public clients, browsers, or user devices.
 * Misuse can lead to serious security breaches and exposure of internal logic or data.
 *
 * ## Example
 * ```kotlin
 * @InternalEndpoint
 * @PostMapping("/api/internal/sync")
 * suspend fun syncData(): ResponseEntity<SyncResult> {
 *     // Accessible only by other internal services
 * }
 * ```
 */
@MustBeDocumented
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class InternalEndpoint