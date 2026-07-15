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
    /// the comparison may silently produce unexpected results. Wrapping the 'tryGet' in
    /// 'coalesce' with a fallback value gives the comparison a defined operand.
    /// </summary>
    public sealed class UnguardedTryGetInComparedValue : LinterRule<LeafCondition>
    {
        private const string RuleDescription =
            "The value condition compares the unguarded 'tryGet' expression '{0}' with '{1}'. 'tryGet' returns null when a path segment is missing; the comparison may silently produce unexpected results. Wrap the 'tryGet' in 'coalesce' with a fallback value.";

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

            // Fires only when the whole value is a single language expression whose outermost function is 'tryGet'.
            // Wrapping it in 'coalesce' makes the outermost function 'coalesce', which supplies a fallback and silences the rule.
            // A 'tryGet' nested inside another function (e.g. concat) has different behavior and is out of scope.
            if (expression.Value.LanguageExpressions.Length != 1 ||
                !string.Equals(UnguardedTryGetInComparedValue.GetOutermostFunctionName(expression.Value.LanguageExpressions[0].Expression), "tryGet", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(expression.Value, expression.Value.LanguageExpressions[0].Expression, expression.Operator.Name),
            };
        }

        /// <summary>
        /// Returns the name of the outermost function in an ARM language expression string,
        /// or null if the expression does not start with a function call.
        /// </summary>
        /// <example>
        /// "[tryGet(field('a'), 'b')]" => "tryGet"
        /// "[coalesce(tryGet(field('a'), 'b'), 'x')]" => "coalesce"
        /// </example>
        private static string? GetOutermostFunctionName(string expression)
        {
            // ARM language expressions start with '['. A function call looks like "[funcName(...)]".
            var body = expression.Substring(1).TrimStart();
            var parenIndex = body.IndexOf('(');
            return parenIndex > 0 ? body.Substring(0, parenIndex).TrimEnd() : null;
        }
    }
}
