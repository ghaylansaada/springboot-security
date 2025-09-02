package io.ghaylan.springboot.security.model.token

/**
 * Interface that must be implemented by all token type enums in projects using this library.
 *
 * This interface defines the token's purpose by associating it with a [TokenAccessScope].
 * It enforces a consistent token classification model across projects, ensuring that each token
 * type is clearly categorized as either `ACCESS`, `REFRESH`, or `INTERNAL`.
 *
 * ## Constraints
 * - **Only one token type must use the `REFRESH` scope** per project.
 * - **Only one token type must use the `INTERNAL` scope** per project.
 * - **Multiple token types can use the `ACCESS` scope** to support different clients or user flows.
 *
 * These constraints are validated by the library at startup to ensure correct token configuration.
 *
 * @property scope The [TokenAccessScope] defining the functional category of this token.
 */
interface TokenAccessPolicy
{
	val scope : TokenAccessScope
}