namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Expressions;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Extensions;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Parsing;
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
        /// Checks if the property has a simple parameterized value. e.g. "[parameters('paramName')]".
        /// This method only checks for the simplest case of a property value that is a plain reference to a string parameter with a known name.
        /// Any other fancy stuff like "parameters('param').value" or "concat(parameters('param'), 'value')" is not considered a **simple** parameterized property.
        /// </summary>
        /// <param name="context">The linter rule evaluation context.</param>
        /// <param name="parameterName">Returns the parameter name if the property is parameterized.</param>
        /// <param name="allowedValues">The parameter allowed values if defined.</param>
        /// <param name="defaultValue">The parameter default value if defined.</param>
        public bool HasSimpleParameterizedValue(LinterContext context, out string parameterName, out string[]? allowedValues, out string? defaultValue)
        {
            parameterName = string.Empty;
            allowedValues = null;
            defaultValue = null;

            if (!this.HasLiteralValue &&
                this.LanguageExpressions.Length == 1 &&
                this.LanguageExpressions[0].IsSimpleParameterReference(out parameterName) &&
                context.Parameters != null &&
                context.Parameters.TryGetValue(parameterName, out var param) &&
                param.TryAsConcreteType<string>(out allowedValues, out defaultValue))
            {
                return true;
            }

            return false;
        }
    }
}
