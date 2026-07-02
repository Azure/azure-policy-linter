// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Extensions for <see cref="GenericObjectProperty{ConditionObject}"/> to flatten and extract conditions.
    /// </summary>
    public static class ConditionFactory
    {
        /// <summary>
        /// Recursively creates conditions from the provided condition property.
        /// </summary>
        /// <param name="condition">The condition.</param>
        /// <param name="conditionPath">The path of the condition expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        /// <param name="parent">The parent expression.</param>
        /// <param name="countExpressionScopes">The parent count expression scopes.</param>
        public static Condition CreateCondition(
            this GenericObjectProperty<ConditionObject> condition,
            IEnumerable<string> conditionPath,
            ITypeMetadata typeMetadata,
            PolicyExpression parent,
            Stack<CountExpressionScope> countExpressionScopes)
        {
            if (condition.Value.IsLeafCondition())
            {
                return new LeafCondition(
                    leafConditionProperty: condition,
                    parentPath: conditionPath.CoalesceEnumerable().ToImmutableArray(),
                    parent: parent,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata);
            }

            return new Quantifier(
                conditionProperty: condition,
                parentPath: conditionPath.CoalesceEnumerable().ToImmutableArray(),
                parent: parent,
                countExpressionScopes: countExpressionScopes,
                typeMetadata: typeMetadata);
        }

        private static bool IsLeafCondition(this ConditionObject? condition)
        {
            return condition?.Field != null || condition?.Count != null || condition?.Value != null;
        }
    }
}
