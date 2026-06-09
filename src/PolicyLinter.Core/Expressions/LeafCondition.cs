// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions
{
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Metadata;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Parsing;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// A policy expression that represents a policy condition leaf expression.
    /// </summary>
    public class LeafCondition : Condition
    {
        /// <summary>
        /// The field accessor in the case of a field condition (e.g. 'field': 'tags.x').
        /// </summary>
        public Property? Field { get; private set; }

        /// <summary>
        /// The value accessor in the case of a value condition (e.g. 'value': 'something
        /// </summary>
        public Property? Value { get; private set; }

        /// <summary>
        /// The count expression in the case of count condition.
        /// </summary>
        public Count? Count { get; }

        /// <summary>
        /// The leaf condition operator and it's value (e.g. 'equals': 'something').
        /// </summary>
        public Property? Operator { get; private set; }

        /// <summary>
        /// Creates a new instance of the <see cref="LeafCondition"/> class.
        /// </summary>
        /// <param name="leafConditionProperty">The leaf condition.</param>
        /// <param name="parentPath">The path of the current expression.</param>
        /// <param name="parent">The parent expression.</param>
        /// <param name="countExpressionScopes">The parent count expression scopes.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public LeafCondition(
            GenericObjectProperty<ConditionObject>? leafConditionProperty,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            Stack<CountExpressionScope> countExpressionScopes,
            ITypeMetadata typeMetadata) : base(leafConditionProperty?.LineNumber, leafConditionProperty?.LinePosition, parentPath, parent)
        {
            if (leafConditionProperty == null)
            {
                // TODO: Better exception
                throw new ArgumentNullException(nameof(leafConditionProperty), "Leaf condition cannot be null.");
            }

            var leafCondition = leafConditionProperty.Value;
            if (leafCondition.Field != null)
            {
                this.Field = new Property(
                    name: "field",
                    value: leafCondition.Field.Value,
                    jTokenMetadata: leafCondition.Field,
                    isFieldAccessor: true,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata);
            }
            else if (leafCondition.Value != null)
            {
                this.Value = new Property(
                    name: "value",
                    value: leafCondition.Value.Value,
                    jTokenMetadata: leafCondition.Value,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata);
            }
            else if (leafCondition.Count != null)
            {
                this.Count = new Count(
                    countProperty: leafCondition.Count,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata,
                    parentPath: this.PathSegments,
                    parent: this);
            }

            // TODO: other leaf expression types.

            if (LeafCondition.TryGetOperatorNameAndValue(leafCondition, out var operatorName, out var operatorValue, out var operatorTokenMetadata))
            {
                this.Operator = new Property(
                    name: operatorName,
                    value: operatorValue,
                    jTokenMetadata: operatorTokenMetadata,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: parent,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata);
            }
            else
            {
                // TODO: Better exception
                throw new ArgumentException(
                    $"Leaf condition '{leafConditionProperty}' does not have a valid operator name and value.",
                    nameof(leafConditionProperty));
            }
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);

            if (this.Field != null)
            {
                this.Field.Visit(visitor);
            }

            if (this.Value != null)
            {
                this.Value.Visit(visitor);
            }

            if (this.Count != null)
            {
                this.Count.Visit(visitor);
            }

            if (this.Operator != null)
            {
                this.Operator.Visit(visitor);
            }
        }


        /// <summary>
        /// Attempts to retrieve the operator name and associated value from the specified <see
        /// cref="ConditionObject"/>.
        /// </summary>
        /// <param name="condition">The <see cref="ConditionObject"/> to evaluate. Can be null.</param>
        /// <param name="operatorName">The operator name if found; otherwise, null.</param>
        /// <param name="value"> The associated value of the operator if the operator is found; otherwise, null.</param>
        /// <param name="metadata"> The metadata associated with the operator property if found; otherwise, null.</param>
        private static bool TryGetOperatorNameAndValue(
            ConditionObject? condition,
            out string operatorName,
            out JToken value,
            out JTokenMetadata? metadata)
        {
            operatorName = string.Empty;
            value = string.Empty;
            metadata = null;

            if (condition?.EqualsOperator != null)
            {
                operatorName = "equals";
                value = condition.EqualsOperator.Value;
                metadata = condition.EqualsOperator;
                return true;
            }
            else if (condition?.NotEquals != null)
            {
                operatorName = "notEquals";
                value = condition.NotEquals.Value;
                metadata = condition.NotEquals;
                return true;
            }
            else if (condition?.Like != null)
            {
                operatorName = "like";
                value = condition.Like.Value;
                metadata = condition.Like;
                return true;
            }
            else if (condition?.NotLike != null)
            {
                operatorName = "notLike";
                value = condition.NotLike.Value;
                metadata = condition.NotLike;
                return true;
            }
            else if (condition?.In != null)
            {
                operatorName = "in";
                value = condition.In.Value;
                metadata = condition.In;
                return true;
            }
            else if (condition?.NotIn != null)
            {
                operatorName = "notIn";
                value = condition.NotIn.Value;
                metadata = condition.NotIn;
                return true;
            }
            else if (condition?.Contains != null)
            {
                operatorName = "contains";
                value = condition.Contains.Value;
                metadata = condition.Contains;
                return true;
            }
            else if (condition?.NotContains != null)
            {
                operatorName = "notContains";
                value = condition.NotContains.Value;
                metadata = condition.NotContains;
                return true;
            }
            else if (condition?.ContainsKey != null)
            {
                operatorName = "containsKey";
                value = condition.ContainsKey.Value;
                metadata = condition.ContainsKey;
                return true;
            }
            else if (condition?.NotContainsKey != null)
            {
                operatorName = "notContainsKey";
                value = condition.NotContainsKey.Value;
                metadata = condition.NotContainsKey;
                return true;
            }
            else if (condition?.Exists != null)
            {
                operatorName = "exists";
                value = condition.Exists.Value;
                metadata = condition.Exists;
                return true;
            }
            else if (condition?.Match != null)
            {
                operatorName = "match";
                value = condition.Match.Value;
                metadata = condition.Match;
                return true;
            }
            else if (condition?.NotMatch != null)
            {
                operatorName = "notMatch";
                value = condition.NotMatch.Value;
                metadata = condition.NotMatch;
                return true;
            }
            else if (condition?.Greater != null)
            {
                operatorName = "greater";
                value = condition.Greater.Value;
                metadata = condition.Greater;
                return true;
            }
            else if (condition?.GreaterOrEquals != null)
            {
                operatorName = "greaterOrEquals";
                value = condition.GreaterOrEquals.Value;
                metadata = condition.GreaterOrEquals;
                return true;
            }
            else if (condition?.Less != null)
            {
                operatorName = "less";
                value = condition.Less.Value;
                metadata = condition.Less;
                return true;
            }
            else if (condition?.LessOrEquals != null)
            {
                operatorName = "lessOrEquals";
                value = condition.LessOrEquals.Value;
                metadata = condition.LessOrEquals;
                return true;
            }
            else if (condition?.MatchInsensitively != null)
            {
                operatorName = "matchInsensitively";
                value = condition.MatchInsensitively.Value;
                metadata = condition.MatchInsensitively;
                return true;
            }
            else if (condition?.NotMatchInsensitively != null)
            {
                operatorName = "notMatchInsensitively";
                value = condition.NotMatchInsensitively.Value;
                metadata = condition.NotMatchInsensitively;
                return true;
            }

            return false;
        }
    }
}
