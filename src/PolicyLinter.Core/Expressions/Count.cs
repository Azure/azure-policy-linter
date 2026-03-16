namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Expressions
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Extensions;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Represents a count policy expression that counts the number of elements in an enumerated array based on a specified condition.
    /// </summary>
    public class Count : PolicyExpression
    {
        /// <summary>
        /// The details of the enumerated array (corresponding to the 'field' or 'value' property in the count expression).
        /// </summary>
        public Property? EnumeratedArray { get; }

        /// <summary>
        /// In the case of value count expressions, this property holds the 'name' given to the enumerated array member so it can be accessed with a current function.
        /// </summary>
        public Property? Name { get; }

        /// <summary>
        /// The where condition (if this is a count expression).
        /// </summary>
        public Condition? Where { get; private set; }

        /// <summary>
        /// The count expression scope.
        /// </summary>
        public CountExpressionScope CountExpressionScope { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Count"/> class.
        /// </summary>
        /// <param name="countProperty">The count object.</param>
        /// <param name="countExpressionScopes">The parent count expression scopes.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        /// <param name="parentPath">The path of the current expression.</param>
        /// <param name="parent">The parent expressions.</param>
        public Count(
            GenericObjectProperty<CountObject>? countProperty,
            Stack<CountExpressionScope> countExpressionScopes,
            ITypeMetadata typeMetadata,
            ImmutableArray<string> parentPath,
            PolicyExpression parent)
            : base(countProperty?.LineNumber, countProperty?.LinePosition, parentPath.Concat("count").ToImmutableArray(), parent)
        {
            if (countProperty == null)
            {
                // TODO: Better exception
                throw new ArgumentNullException(nameof(countProperty), "Count object can't be null.");
            }

            var count = countProperty.Value;

            if (count.Field != null)
            {
                this.EnumeratedArray = new Property(
                    name: "field",
                    value: count.Field.Value,
                    jTokenMetadata: count.Field,
                    isFieldAccessor: true,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata);

                // This shouldn't happen for valid policies- policy authoring won't allow creating count field expressions
                // where the field is something line a parameter reference. However, the linter can still be invoked with such invalid policy.
                // TODO: Throw linter exception, or even swallow the exception altogether and skip the parsing of this expression so
                // that we can at least do some linting.
                if (this.EnumeratedArray.FieldAccessorReference?.IsResolved != true)
                {
                    throw new Exception("count field reference is not resolved");
                }

                this.CountExpressionScope = CountExpressionScope.FieldScope(this.EnumeratedArray.FieldAccessorReference.Identifier);
            }
            else if (count.Value != null)
            {
                this.EnumeratedArray = new Property(
                    name: "value",
                    value: count.Value.Value,
                    jTokenMetadata: count.Value,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata);

                if (count.Name != null)
                {
                    this.Name = new Property(
                        name: "name",
                        value: count.Name.Value,
                        jTokenMetadata: count.Name,
                        isFieldAccessor: false,
                        parentPath: this.PathSegments,
                        parent: this,
                        countExpressionScopes: countExpressionScopes,
                        typeMetadata: typeMetadata);

                    this.CountExpressionScope = CountExpressionScope.ValueScope(this.Name.Value.ToStringValue()!);
                }
                else
                {
                    this.CountExpressionScope = CountExpressionScope.ValueScope(CountExpressionScope.DefaultValueCountScopeIdentifier);
                }
            }
            else
            {
                throw new ArgumentException("Unsupported count expression.");
            }

            if (this.EnumeratedArray != null)
            {
                countExpressionScopes.Push(this.CountExpressionScope);

                this.Where = count.Where?.CreateCondition(
                    conditionPath: this.PathSegments.Concat("where"),
                    typeMetadata: typeMetadata,
                    parent: this,
                    countExpressionScopes: countExpressionScopes);

                _ = countExpressionScopes.Pop();
            }
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);

            this.EnumeratedArray?.Visit(visitor);
            this.Name?.Visit(visitor);
            this.Where?.Visit(visitor);
        }
    }
}
