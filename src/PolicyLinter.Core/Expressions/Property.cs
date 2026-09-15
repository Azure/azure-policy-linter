// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Represents a policy definition property and its value.
    /// </summary>
    /// <example>
    /// { "field": "tags.x", "equals": "y" } represents 2 properties, one for the field accessor and another for the operator.
    /// </example>
    public class Property : PolicyExpression
    {
        /// <summary>
        /// The property name.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The property value as specified in the policy definition.
        /// </summary>
        public JToken Value { get; }

        /// <summary>
        /// Contains a field reference if this property is a field accessor reference (e.g. { "field": "tags.x" }).
        /// </summary>
        public Reference? FieldAccessorReference { get; }

        /// <summary>
        /// Any template language expressions within the property value (e.g. [field(concat('a', 'b'))]).
        /// </summary>
        public ImmutableArray<TemplateLanguageExpression> LanguageExpressions { get; }

        /// <summary>
        /// Whether the property value is literal (i.e. has no template language expressions).
        /// </summary>
        public bool HasLiteralValue => !this.LanguageExpressions.Any();

        /// <summary>
        /// Creates a new instance of the <see cref="Property"/> class.
        /// </summary>
        /// <param name="name">The property name.</param>
        /// <param name="value">The property value.</param>
        /// <param name="jTokenMetadata">The metadata of the JSON object from which this property was parsed.</param>
        /// <param name="isFieldAccessor">Whether the property value represents a field accessor.</param>
        /// <param name="parentPath">The path of the parent of the current expression.</param>
        /// <param name="parent">The parent of the property.</param>
        /// <param name="countExpressionScopes">The count expression scopes above the property (needed for property value reference resolution).</param>
        /// <param name="typeMetadata">The type metadata (needed for property value reference resolution).</param>
        public Property(
            string name,
            JToken value,
            JTokenMetadata? jTokenMetadata,
            bool isFieldAccessor,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            Stack<CountExpressionScope> countExpressionScopes,
            ITypeMetadata typeMetadata) : base(jTokenMetadata?.LineNumber, jTokenMetadata?.LinePosition, parentPath.Concat(name).ToImmutableArray(), parent)
        {
            this.Name = name;
            this.Value = value;

            this.LanguageExpressions = TemplateLanguageExpression
                .ExtractFromJToken(
                    token: value,
                    jTokenMetadata: jTokenMetadata,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata,
                    path: this.PathSegments,
                    parent: this)
                .ToImmutableArray();

            if (isFieldAccessor)
            {
                if (value.Type != JTokenType.String)
                {
                    throw new ArgumentException($"Expected property value to be string when called with: {nameof(isFieldAccessor)}=true, but called with {value.Type} instead");
                }

                this.FieldAccessorReference = Reference.CreateFieldAccessorReference(
                    fieldAccessor: value.ToStringValue()!,
                    fieldAccessorLanguageExpression: this.LanguageExpressions.SingleOrDefault(),
                    path: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata,
                    jTokenMetadata: jTokenMetadata);
            }

        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);

            if (this.FieldAccessorReference != null)
            {
                this.FieldAccessorReference.Visit(visitor);
            }

            foreach (var languageExpression in this.LanguageExpressions)
            {
                // If this is a field accessor, any references in the value have already been visited when the field accessor reference was visited.
                // We don't want to visit them again when visiting the language expression.
                languageExpression.Visit(visitor, skipVisitingReferences: this.FieldAccessorReference != null);
            }
        }

        /// <summary>
        /// Gets the allowed and default values of a bare string-parameter reference.
        /// </summary>
        /// <param name="context">The linter rule evaluation context.</param>
        /// <param name="parameterName">Returns the parameter name if the property is parameterized.</param>
        /// <param name="allowedValues">The parameter allowed values if defined.</param>
        /// <param name="defaultValue">The parameter default value if defined.</param>
        public bool HasSimpleParameterizedValue(LinterContext context, out string parameterName, out string[]? allowedValues, out string? defaultValue)
        {
            allowedValues = null;
            defaultValue = null;

            return this.HasSimpleParameterizedValue(
                    parameters: context.Parameters,
                    parameterName: out parameterName,
                    parameter: out var parameter) &&
                parameter.TryAsConcreteType<string>(allowedValues: out allowedValues, defaultValue: out defaultValue);
        }

        /// <summary>
        /// Resolves a bare parameter reference to its definition, including its allowed and default values.
        /// </summary>
        /// <param name="parameters">Policy parameters, keyed by parameter name.</param>
        /// <param name="parameterName">The name used in the reference.</param>
        /// <param name="parameter">The referenced parameter definition, or null if unresolved.</param>
        public bool HasSimpleParameterizedValue(
            ImmutableDictionary<string, Parameter>? parameters,
            out string parameterName,
            [NotNullWhen(true)] out Parameter? parameter)
        {
            parameterName = string.Empty;
            parameter = null;

            return this.Value.Type == JTokenType.String &&
                !this.HasLiteralValue &&
                this.LanguageExpressions.Length == 1 &&
                this.LanguageExpressions[0].IsSimpleParameterReference(parameterName: out parameterName) &&
                parameters != null &&
                parameters.TryGetValue(key: parameterName, value: out parameter);
        }
    }
}
