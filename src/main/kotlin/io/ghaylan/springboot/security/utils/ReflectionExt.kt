package io.ghaylan.springboot.security.utils

import java.lang.reflect.Method

/**
 * Generates a unique identifier for this Java/Kotlin method.
 *
 * The identifier is composed of:
 * 1. Fully qualified class name
 * 2. Method name
 * 3. Parameter types
 *
 * Uses `#` to separate the class and method for clarity.
 * Ensures uniqueness even for overloaded methods within the same class.
 *
 * Example output: `com.example.MyController#getUser(String,int)`
 *
 * @receiver The `Method` instance to generate the identifier for.
 * @return A unique, human-readable identifier for the method.
 */
fun Method.getUniqueIdentifier(): String
{
    val clazz = this.declaringClass.name
    val method = this.name
    val params = this.parameterTypes.joinToString(",") { it.simpleName }
    return "$clazz#$method($params)"
}