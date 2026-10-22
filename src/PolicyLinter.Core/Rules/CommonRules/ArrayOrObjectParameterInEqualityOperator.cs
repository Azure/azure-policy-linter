// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Detects equality conditions that use an Array or Object parameter as the comparison value.
    /// </summary>
    public sealed class ArrayOrObjectParameterInEqualityOperator : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Array or Object Parameter in Equality Operator";
        private const string RuleDescription =
            "The '{0}' operator compares with parameter '{1}' of type '{2}'. This operator needs a single value, so the condition is not valid.";

        /// <summary>
        /// Initializes a new instance of the <see cref="ArrayOrObjectParameterInEqualityOperator"/> class.
        /// </summary>
        public ArrayOrObjectParameterInEqualityOperator() : base(
            identifier: "array-or-object-parameter-in-equality-operator",
            category: Category.BestPractices,
            title: ArrayOrObjectParameterInEqualityOperator.RuleTitle,
            descriptionFormat: ArrayOrObjectParameterInEqualityOperator.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var comparisonOperator = expression.Operator;
            if (comparisonOperator != null &&
                (comparisonOperator.Name.EqualsOrdinalInsensitively("equals") ||
                comparisonOperator.Name.EqualsOrdinalInsensitively("notEquals")) &&
                comparisonOperator.IsSimpleParameterReference(parameterName: out var parameterName) &&
                context.Parameters != null &&
                context.Parameters.TryGetValue(key: parameterName, value: out var parameter) &&
                (parameter.Type.EqualsOrdinalInsensitively(PolicyParameterType.Array) ||
                parameter.Type.EqualsOrdinalInsensitively(PolicyParameterType.Object)))
            {
                return new[]
                {
                    this.CreateError(comparisonOperator, comparisonOperator.Name, parameterName, parameter.Type),
                };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
