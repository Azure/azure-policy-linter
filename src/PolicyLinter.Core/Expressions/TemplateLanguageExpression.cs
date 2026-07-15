// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using global::Azure.Deployments.Expression.Engines;
    using global::Azure.Deployments.Expression.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Utilities;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Represents a template language expression string (e.g. [field(concat('a', 'b'))]).
    /// </summary>
    /// <remarks>
    /// This class contains the expression and details about references\functions within it, but it doesn't provide a way to traverse the expression tree.
    /// </remarks>
    public class TemplateLanguageExpression : PolicyExpression
    {
        /// <summary>
        /// The parsed language expression.
        /// </summary>
        /// <remarks>
        /// This property is private by design. We don't want linter rules to use it because it'll prevent us from ever getting rid of the dependency on the policy engine.
        /// </remarks>
        private LanguageExpression LanguageExpression { get; }

        /// <summary>
        /// The raw language expression string.
        /// </summary>
        public string Expression { get; }

        /// <summary>
        /// Any references within the expression (e.g. a parameters() function).
        /// This is an array because complex values can have multiple references within them. For example the JSON array: [ parameters('a'), field('b') ] has 2 references.
        /// </summary>
        public ImmutableArray<Reference> References { get; }

        /// <summary>
        /// The reference kind of the root language expression if it is a reference.
        /// </summary>
        /// <example>
        /// [field('a')] => ReferenceKind.Field
        /// [concat(field('a'), 'b')] => null
        /// </example>
        /// <remarks>
        /// When this variable is not null, it can be expected that the <see cref="References"/> array will contain only one reference of the same kind.
        /// </remarks>
        public ReferenceKind? ReferenceKind { get; }

        /// <summary>
        /// Extracts template language expressions from a JToken.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="jTokenMetadata">Metadata of the JToken.</param>
        /// <param name="countExpressionScopes">Parent count expression scopes.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        /// <param name="path">The path to the expression.</param>
        /// <param name="parent">The parent of the expression.</param>
        public static TemplateLanguageExpression[] ExtractFromJToken(
            JToken token,
            JTokenMetadata? jTokenMetadata,
            Stack<CountExpressionScope> countExpressionScopes,
            ITypeMetadata typeMetadata,
            ImmutableArray<string> path,
            PolicyExpression parent)
        {
            var results = new List<TemplateLanguageExpression>();
            JsonUtility.WalkJsonRecursive(
                root: token,
                propertyAction: (property) =>
                {
                    if (ExpressionsEngine.IsLanguageExpression(property.Name))
                    {
                        results.Add(new TemplateLanguageExpression(
                            expression: property.Name,
                            jTokenMetadata: jTokenMetadata,
                            countExpressionScopes: countExpressionScopes,
                            typeMetadata: typeMetadata,
                            path: path,
                            parent: parent));
                    }
                },
                tokenAction: (token) =>
                {
                    if (token.Type == JTokenType.String && ExpressionsEngine.IsLanguageExpression(token.ToStringValue()))
                    {
                        results.Add(new TemplateLanguageExpression(
                            expression: token.ToStringValue()!,
                            jTokenMetadata: jTokenMetadata,
                            countExpressionScopes: countExpressionScopes,
                            typeMetadata: typeMetadata,
                            path: path,
                            parent: parent));
                    }
                });

            return results.ToArray();
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            this.Visit(visitor, skipVisitingReferences: false);
        }

        /// <summary>
        /// Visits the expression and its references with the given visitor.
        /// References will only be visited if <paramref name="skipVisitingReferences"/> is false.
        /// </summary>
        /// <param name="visitor">The visitor.</param>
        /// <param name="skipVisitingReferences">Whether to skip visiting any child references.</param>
        /// <remarks>
        /// This is needed because in the case of field accessor containing language expressions,
        /// the references in the language expression will be marked as resolution dependencies of the field accessor and will be visited when that field reference is visited.
        /// We don't want to visit them twice.
        /// </remarks>
        internal void Visit(PolicyExpressionVisitor visitor, bool skipVisitingReferences)
        {
            visitor.Visit?.Invoke(this);

            if (skipVisitingReferences)
            {
                return;
            }

            foreach (var reference in this.References)
            {
                reference.Visit(visitor);
            }
        }


        /// <summary>
        /// Whether the expression contains any unresolved references.
        /// </summary>
        public bool HasUnresolvedReferences()
        {
            return this.References.Any(reference => !reference.IsResolved);
        }

        /// <summary>
        /// Creates a new instance of the <see cref="TemplateLanguageExpression"/> class.
        /// </summary>
        private TemplateLanguageExpression(
            string expression,
            JTokenMetadata? jTokenMetadata,
            Stack<CountExpressionScope> countExpressionScopes,
            ITypeMetadata typeMetadata,
            ImmutableArray<string> path,
            PolicyExpression parent) : base(jTokenMetadata?.LineNumber, jTokenMetadata?.LinePosition, path, parent)
        {
            if (!ExpressionsEngine.IsLanguageExpression(expression))
            {
                throw new ArgumentException($"The provided expression: {expression} is not a valid language expression.", nameof(expression));
            }

            this.Expression = expression;
            this.LanguageExpression = ExpressionsEngine.ParseLanguageExpression(expression);
            if (Reference.IsReferenceFunction(this.LanguageExpression, out var kind))
            {
                this.ReferenceKind = kind;
            }

            var references = new List<Reference>();

            Reference.FromLanguageExpression(
                languageExpression: this.LanguageExpression,
                path: path,
                parent: this,
                countExpressionScopes: countExpressionScopes,
                typeMetadata: typeMetadata,
                jTokenMetadata: jTokenMetadata,
                results: references);

            this.References = references.ToImmutableArray();

        }

        /// <summary>
        /// Checks if this expression is a simple parameter reference like "[parameters('paramName')]".
        /// This method only checks for the simplest case - a plain reference to a parameter with a known name.
        /// Any other fancy stuff like "parameters('param').value" or "concat(parameters('param'), 'value')" is not considered a simple parameter reference.
        /// </summary>
        /// <param name="parameterName">Returns the parameter name if this is a simple parameter reference.</param>
        /// <returns>True if this is a simple parameter reference, false otherwise.</returns>
        public bool IsSimpleParameterReference(out string parameterName)
        {
            parameterName = string.Empty;

            // Check if this is a parameter reference at the root level
            if (this.ReferenceKind != Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.ReferenceKind.PolicyParameterName)
            {
                return false;
            }

            // Check if we have exactly one reference and it's resolved
            if (this.References.Length != 1 || !this.References[0].IsResolved)
            {
                return false;
            }

            var reference = this.References[0];

            // Check if the underlying language expression is a plain function call without property selectors
            if (this.LanguageExpression is FunctionExpression functionExpression &&
                functionExpression.Function.Equals("parameters", StringComparison.OrdinalIgnoreCase) &&
                functionExpression.Parameters.Length == 1 &&
                (functionExpression.Properties == null || functionExpression.Properties.Length == 0))
            {
                parameterName = reference.Identifier;
                return true;
            }

            return false;
        }
    }
}
