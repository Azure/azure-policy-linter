namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Expressions;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Represents a policy condition quantifier (allOf, anyOf) as well as "not" expressions.
    /// </summary>
    public class Quantifier : Condition
    {
        /// <summary>
        /// The allOf quantifier conditions (if this is an allOf quantifier).
        /// </summary>
        public ImmutableArray<Condition>? AllOf { get; private set; }

        /// <summary>
        /// The anyOf quantifier conditions (if this is an anyOf quantifier).
        /// </summary>
        public ImmutableArray<Condition>? AnyOf { get; private set; }

        /// <summary>
        /// The not conditions (if this is a not quantifier).
        /// </summary>
        /// <remarks>
        /// Technically 'not' is not a quantifier, but it behaves similarly to 'allOf' and 'anyOf' in that it contains child conditions.
        /// </remarks>
        public Condition? Not { get; private set; }

        /// <summary>
        /// Creates and returns a condition from the quantifier expression.
        /// </summary>
        /// <param name="conditionProperty">The condition property.</param>
        /// <param name="parentPath">The path of the current expression.</param>
        /// <param name="parent">The parent expression.</param>
        /// <param name="countExpressionScopes">The parent count expression scopes.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public Quantifier(
            GenericObjectProperty<ConditionObject>? conditionProperty,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            Stack<CountExpressionScope> countExpressionScopes,
            ITypeMetadata typeMetadata)
            : base(
                  lineNumber: Quantifier.FindEffectiveMetadata(conditionProperty)?.LineNumber,
                  linePosition: Quantifier.FindEffectiveMetadata(conditionProperty)?.LinePosition,
                  path: parentPath.Concat(Quantifier.GetQuantifierName(conditionProperty)).ToImmutableArray(),
                  parent: parent)
        {
            if (conditionProperty == null)
            {
                throw new ArgumentNullException(nameof(conditionProperty), "Condition property cannot be null.");
            }

            var condition = conditionProperty.Value;
            if (condition.AllOf != null)
            {
                this.AllOf = condition.AllOf.Value.Select((c, i) => c.CreateCondition(
                    conditionPath: parentPath.CoalesceEnumerable().Concat($"allOf[{i}]").ToImmutableArray(),
                    typeMetadata: typeMetadata,
                    parent: this,
                    countExpressionScopes: countExpressionScopes)).ToImmutableArray();
            }
            else if (condition.AnyOf != null)
            {
                this.AnyOf = condition.AnyOf.Value.Select((c, i) => c.CreateCondition(
                    conditionPath: parentPath.CoalesceEnumerable().Concat($"anyOf[{i}]").ToImmutableArray(),
                    typeMetadata: typeMetadata,
                    parent: this,
                    countExpressionScopes: countExpressionScopes)).ToImmutableArray();
            }
            else if (condition.Not != null)
            {
                this.Not = condition.Not?.Value.CreateCondition(
                    conditionPath: parentPath.CoalesceEnumerable().Concat("not").ToImmutableArray(),
                    typeMetadata: typeMetadata,
                    parent: this,
                    countExpressionScopes: countExpressionScopes);
            }
            else
            {
                throw new ArgumentException("Condition property must contain either 'allOf', 'anyOf', or 'not'.", nameof(conditionProperty));
            }
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);

            if (this.AllOf != null)
            {
                foreach (var child in this.AllOf)
                {
                    child.Visit(visitor);
                }
            }

            if (this.AnyOf != null)
            {
                foreach (var child in this.AnyOf)
                {
                    child.Visit(visitor);
                }
            }

            if (this.Not != null)
            {
                this.Not.Visit(visitor);
            }
        }

        private static JTokenMetadata? FindEffectiveMetadata(GenericObjectProperty<ConditionObject>? conditionProperty)
        {
            return conditionProperty?.Value.AllOf as JTokenMetadata ??
                   conditionProperty?.Value.AnyOf as JTokenMetadata ??
                   conditionProperty?.Value.Not as JTokenMetadata ??
                   null;
        }

        private static string GetQuantifierName(GenericObjectProperty<ConditionObject>? conditionProperty)
        {
            if (conditionProperty?.Value.AllOf != null)
            {
                return "allOf";
            }
            else if (conditionProperty?.Value.AnyOf != null)
            {
                return "anyOf";
            }
            else if (conditionProperty?.Value.Not != null)
            {
                return "not";
            }
            else
            {
                return "unknown";
            }
        }
    }
}
