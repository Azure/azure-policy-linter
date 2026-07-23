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
    /// Detects directly nested not conditions that cancel each other out.
    /// </summary>
    public sealed class DirectlyNestedNotCondition : LinterRule<Quantifier>
    {
        private const string RuleTitle = "Directly Nested Not Condition";

        private const string RuleDescription =
            "The directly nested 'not' operators negate the same condition twice and are mechanically equivalent to the inner condition. Remove both directly nested 'not' operators.";

        /// <summary>
        /// Initializes a new instance of the <see cref="DirectlyNestedNotCondition"/> class.
        /// </summary>
        public DirectlyNestedNotCondition() : base(
            identifier: "directly-nested-not-condition",
            category: Category.BestPractices,
            title: DirectlyNestedNotCondition.RuleTitle,
            descriptionFormat: DirectlyNestedNotCondition.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Quantifier expression, LinterContext context)
        {
            if (expression.Not is not Quantifier nestedNot || nestedNot.Not == null)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateInformational(expression: nestedNot)
            };
        }
    }
}
