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
    /// Detects nested not conditions that cancel each other out.
    /// </summary>
    public sealed class NestedNotCondition : LinterRule<Quantifier>
    {
        private const string RuleTitle = "Nested Not Condition";

        private const string RuleDescription =
            "Two nested 'not' operators negate the same condition, which adds nesting without changing the result. Remove both.";

        /// <summary>
        /// Initializes a new instance of the <see cref="NestedNotCondition"/> class.
        /// </summary>
        public NestedNotCondition() : base(
            identifier: "nested-not-condition",
            category: Category.BestPractices,
            title: NestedNotCondition.RuleTitle,
            descriptionFormat: NestedNotCondition.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Quantifier expression, LinterContext context)
        {
            if (expression.Not != null && // This is a 'not' quantifier
                NestedNotCondition.ExpressionIsANotQuantifier(expression.Parent) &&  // The parent is a not quantifier
                !NestedNotCondition.ExpressionIsANotQuantifier(expression.Not)  // The child is NOT a not quantifier (i.e. this is the 'leaf not')
                )
            {
                return new[]
                {
                    this.CreateInformational(expression: expression)
                };
            }

            return Array.Empty<LinterOutput>();
        }

        public static bool ExpressionIsANotQuantifier(PolicyExpression? expression)
        {
            return expression is Quantifier quantifier && quantifier.Not != null;
        }
    }
}
