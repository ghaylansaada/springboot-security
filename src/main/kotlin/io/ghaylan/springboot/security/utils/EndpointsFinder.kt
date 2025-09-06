package io.ghaylan.springboot.security.utils

import org.springframework.context.ApplicationContext
import org.springframework.http.HttpMethod
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping
import org.springframework.web.util.pattern.PathPatternParser
import java.lang.reflect.Method
import kotlin.collections.ifEmpty
import kotlin.collections.plus
import kotlin.collections.toList
import kotlin.jvm.java
import kotlin.text.ifEmpty
import kotlin.text.replace
import kotlin.text.trimEnd
import kotlin.text.trimStart
import kotlin.to

/**
 * Utility for discovering all REST endpoints declared in a Spring WebFlux application.
 *
 * This class inspects the `RequestMappingHandlerMapping` registered in the
 * application context and extracts the mapping between:
 *
 * - **Controller method** (`Method`)
 * - **HTTP endpoint** (`HttpMethod` + normalized path)
 *
 * ### Typical Use Cases
 * - Generating endpoint documentation
 * - Implementing request auditing or logging
 * - Enforcing custom security rules at startup
 *
 * ### Example
 * ```kotlin
 * val endpoints = EndpointsFinder.find(appContext) { method, (httpMethod, path) ->
 *     "${method.declaringClass.simpleName}#${method.name} -> $httpMethod $path"
 * }
 * endpoints.forEach(::println)
 * ```
 */
object EndpointsFinder
{

    /**
     * Finds all REST endpoints exposed by `@RestController` classes in the given application context.
     *
     * @param appContext Spring application context containing WebFlux configuration
     * @param onMethod   Callback applied for each discovered method–endpoint pair
     * @return List of callback results, one per discovered endpoint
     *
     * ### Notes
     * - Only methods declared in classes annotated with `@RestController` are considered.
     * - Both class-level and method-level `@RequestMapping` annotations are merged.
     * - If no HTTP method is specified on `@RequestMapping`, it defaults to **GET**.
     */
    fun <T> find(
        appContext : ApplicationContext,
        onMethod : (method : Method, endpoint : Pair<HttpMethod, String>) -> T)
    : List<T>
    {
        val pathParser = PathPatternParser()

        val handlerMapping: RequestMappingHandlerMapping = appContext.getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping::class.java)

        val result = ArrayList<T>(handlerMapping.handlerMethods.size)

        for ((info, handlerMethod) in handlerMapping.handlerMethods)
        {
            val method = handlerMethod.method
            val clazz = method.declaringClass

            if (!clazz.isAnnotationPresent(RestController::class.java)) continue

            val httpMethods = info.methodsCondition.methods
                .ifEmpty { setOf(RequestMethod.GET) }

            val patterns = info.patternsCondition.patterns
                .ifEmpty { setOf(pathParser.parse("/")) }

            for (m in httpMethods)
            {
                for (pattern in patterns)
                {
                    result.add(onMethod(method, HttpMethod.valueOf(m.name) to pattern.patternString))
                }
            }
        }

        return result
    }


    /**
     * Extracts all endpoints defined on a given controller method.
     *
     * Combines class-level `@RequestMapping` base paths with method-level
     * annotations such as `@GetMapping`, `@PostMapping`, etc.
     *
     * @param clazz  Controller class containing the method
     * @param method Controller method to inspect
     * @return List of `(HttpMethod, path)` pairs representing resolved endpoints
     */
    private fun getMethods(
        clazz: Class<*>,
        method: Method
    ) : List<Pair<HttpMethod, String>>
    {
        val classAnnotation = clazz.getAnnotation(RequestMapping::class.java)

        val basePaths: List<String> = ((classAnnotation?.value?.asList() ?: emptyList()) + (classAnnotation?.path?.asList() ?: emptyList()))
                .ifEmpty { listOf("") }

        val result = ArrayList<Pair<HttpMethod, String>>(4)

        for (annotation in method.annotations)
        {
            when (annotation)
            {
                is GetMapping    -> addEndpoints(HttpMethod.GET, basePaths, result, annotation.value, annotation.path)
                is PostMapping   -> addEndpoints(HttpMethod.POST, basePaths, result, annotation.value, annotation.path)
                is PutMapping    -> addEndpoints(HttpMethod.PUT, basePaths, result, annotation.value, annotation.path)
                is PatchMapping  -> addEndpoints(HttpMethod.PATCH, basePaths, result, annotation.value, annotation.path)
                is DeleteMapping -> addEndpoints(HttpMethod.DELETE, basePaths, result, annotation.value, annotation.path)
                is RequestMapping -> {
                    val paths = (annotation.value.asList() + annotation.path.asList()).ifEmpty { listOf("") }

                    val methods = if (annotation.method.isEmpty()) arrayOf(RequestMethod.GET) else annotation.method

                    for (m in methods)
                    {
                        for (base in basePaths)
                        {
                            for (path in paths)
                            {
                                result.add(HttpMethod.valueOf(m.name) to normalizePath(base, path))
                            }
                        }
                    }
                }
            }
        }

        return result
    }


    /**
     * Adds endpoints to the target list by combining HTTP method,
     * class-level base paths, and method-level paths.
     *
     * @param httpMethod HTTP method to associate with paths
     * @param basePaths  List of base paths from class-level `@RequestMapping`
     * @param target     List to collect results
     * @param arrays     Arrays of paths from method-level annotations
     */
    private fun addEndpoints(
        httpMethod: HttpMethod,
        basePaths: List<String>,
        target: MutableList<Pair<HttpMethod, String>>,
        vararg arrays: Array<String>)
    {
        val paths = arrays.asSequence().flatMap { it.asSequence() }.toList().ifEmpty { listOf("") }

        for (base in basePaths)
        {
            for (path in paths)
            {
                target.add(httpMethod to normalizePath(base, path))
            }
        }
    }


    /**
     * Normalizes the combination of a base path and method path into a clean URI.
     *
     * Ensures:
     * - No duplicate slashes
     * - Root path defaults to `/`
     *
     * @param base Class-level path
     * @param path Method-level path
     * @return Normalized full path
     */
    private fun normalizePath(base: String, path: String): String
    {
        if (base.isEmpty()) return path.ifEmpty { "/" }

        if (path.isEmpty()) return base

        return (base.trimEnd('/') + "/" + path.trimStart('/')).replace("//", "/")
    }


    /**
     * Helper extension for safely converting a nullable string array to a list.
     */
    private fun Array<String>?.asList(): List<String> = this?.toList() ?: emptyList()
}