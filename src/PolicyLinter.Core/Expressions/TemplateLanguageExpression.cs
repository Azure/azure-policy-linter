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
    /// The parsed expression is in <see cref="Root"/>, and the references in it are in <see cref="References"/>.
    /// </remarks>
    public class TemplateLanguageExpression : PolicyExpression
    {
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
        /// The parsed expression: a <see cref="TemplateFunctionCall"/> (e.g. "[concat(field('a'), 'b')]") or a <see cref="TemplateLiteralValue"/> (e.g. "[1]").
        /// </summary>
        public TemplateLanguageNode Root { get; }

        /// <summary>
        /// Whether the expression is the entire property value, e.g. { "value": "[field('a')]" },
        /// and not part of an array or object value, or a property name.
        /// </summary>
        public bool IsEntireValue { get; }

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
            var root = token;
            JsonUtility.WalkJsonRecursive(
                root: token,
                propertyAction: (property) =>
                {
                    if (ExpressionsEngine.IsLanguageExpression(property.Name))
                    {
                        results.Add(new TemplateLanguageExpression(
                            expression: property.Name,
                            isEntireValue: false,
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
                            isEntireValue: object.ReferenceEquals(token, root),
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
            this.Root.Visit(visitor);

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
            bool isEntireValue,
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
            this.IsEntireValue = isEntireValue;
            this.Root = TemplateLanguageNode.Create(
                expression: ExpressionsEngine.ParseLanguageExpression(expression),
                parent: this,
                isConditionallyEvaluated: false,
                guardCondition: null);

            var references = new List<Reference>();
            Reference.FromLanguageExpression(
                node: this.Root,
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

            if (this.Root is TemplateFunctionCall { Reference: { Kind: ReferenceKind.PolicyParameterName, IsResolved: true } reference } call &&
                call.Arguments.Length == 1 &&
                call.Selectors.Length == 0)
            {
                parameterName = reference.Identifier;
                return true;
            }

            return false;
        }
    }
}
