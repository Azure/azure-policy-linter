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
    public sealed class NonScalarParameterInEqualityCondition : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Non-Scalar Parameter in Equality Condition";
        private const string RuleDescription =
            "The '{0}' condition uses parameter '{1}' of type '{2}' as its comparison value. Equality conditions require a scalar value. Use 'in' or 'notIn' for an array, or the 'equals()' function in a 'value' condition for complete-value equality.";

        /// <summary>
        /// Initializes a new instance of the <see cref="NonScalarParameterInEqualityCondition"/> class.
        /// </summary>
        public NonScalarParameterInEqualityCondition() : base(
            identifier: "non-scalar-parameter-in-equality-condition",
            category: Category.BestPractices,
            title: NonScalarParameterInEqualityCondition.RuleTitle,
            descriptionFormat: NonScalarParameterInEqualityCondition.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var comparisonOperator = expression.Operator;
            if (comparisonOperator == null ||
                (!comparisonOperator.Name.EqualsOrdinalInsensitively("equals") &&
                !comparisonOperator.Name.EqualsOrdinalInsensitively("notEquals")) ||
                !comparisonOperator.IsSimpleParameterReference(parameterName: out var parameterName) ||
                context.Parameters == null ||
                !context.Parameters.TryGetValue(key: parameterName, value: out var parameter) ||
                (!parameter.Type.EqualsOrdinalInsensitively(PolicyParameterType.Array) &&
                !parameter.Type.EqualsOrdinalInsensitively(PolicyParameterType.Object)))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateError(comparisonOperator, comparisonOperator.Name, parameterName, parameter.Type),
            };
        }
    }
}
