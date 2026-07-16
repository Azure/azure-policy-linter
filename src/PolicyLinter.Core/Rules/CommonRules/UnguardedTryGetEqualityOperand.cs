// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Flags an 'equals' or 'notEquals' condition whose value expression has 'tryGet' as its
    /// outermost function. 'tryGet' returns null when the property is missing, and
    /// 'equals'/'notEquals' throw on a null value, so the policy fails at evaluation time.
    /// </summary>
    public sealed class UnguardedTryGetEqualityOperand : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Unguarded TryGet Equality Operand";
        private const string RuleDescription =
            "The '{0}' operator's value is a 'tryGet(...)' expression, which returns null when the property is missing. The '{0}' operator throws on a null value at evaluation time. Wrap the expression in 'coalesce(..., <fallback>)' so the value is never null.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedTryGetEqualityOperand"/> class.
        /// </summary>
        public UnguardedTryGetEqualityOperand() : base(
            identifier: "unguarded-tryget-equality-operand",
            category: Category.BestPractices,
            title: UnguardedTryGetEqualityOperand.RuleTitle,
            descriptionFormat: UnguardedTryGetEqualityOperand.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            if (expression.Operator == null)
            {
                return Array.Empty<LinterOutput>();
            }

            var operatorName = expression.Operator.Name;
            if (!string.Equals(operatorName, "equals", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(operatorName, "notEquals", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<LinterOutput>();
            }

            if (expression.Operator.LanguageExpressions.Length != 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var valueExpression = expression.Operator.LanguageExpressions[0];
            if (!string.Equals(valueExpression.RootFunctionName, "tryGet", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateError(expression.Operator, operatorName),
            };
        }
    }
}
