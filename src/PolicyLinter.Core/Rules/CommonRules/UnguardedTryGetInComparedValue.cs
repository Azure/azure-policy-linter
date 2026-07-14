// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;

    /// <summary>
    /// Flags a 'value' condition whose value is an unguarded 'tryGet' expression compared
    /// with 'equals' or 'notEquals'. 'tryGet' returns null when a path segment is missing;
    /// the null is coerced to empty string, so the comparison silently never matches. Wrapping
    /// the 'tryGet' in 'coalesce' with a fallback value gives the comparison a defined operand.
    /// </summary>
    public sealed class UnguardedTryGetInComparedValue : LinterRule<LeafCondition>
    {
        private const string RuleDescription =
            "The value condition compares the unguarded 'tryGet' expression '{0}' with '{1}'. 'tryGet' returns null when a path segment is missing, which is coerced to empty string, so the condition silently never matches. Wrap the 'tryGet' in 'coalesce' with a fallback value.";

        private static readonly OrdinalInsensitiveHashSet EqualityOperators = new OrdinalInsensitiveHashSet
        {
            "equals",
            "notEquals",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedTryGetInComparedValue"/> class.
        /// </summary>
        public UnguardedTryGetInComparedValue() : base(
            identifier: "unguarded-tryget-in-compared-value",
            category: Category.BestPractices,
            title: "Unguarded tryGet in Compared Value",
            descriptionFormat: UnguardedTryGetInComparedValue.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            if (expression.Value == null ||
                expression.Operator == null ||
                !UnguardedTryGetInComparedValue.EqualityOperators.Contains(expression.Operator.Name))
            {
                return Array.Empty<LinterOutput>();
            }

            // A 'value' whose outermost function is 'tryGet' is unguarded; wrapping it in 'coalesce' makes the
            // outermost function 'coalesce' instead, which supplies a fallback and silences the rule.
            if (expression.Value.LanguageExpressions.Length != 1 ||
                !string.Equals(expression.Value.LanguageExpressions[0].OutermostFunctionName, "tryGet", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(expression.Value, expression.Value.LanguageExpressions[0].Expression, expression.Operator.Name),
            };
        }
    }
}
