// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using global::Azure.Deployments.Expression.Engines;
    using global::Azure.Deployments.Expression.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Flags a 'value' condition whose value is an unguarded 'tryGet' expression compared
    /// with 'equals' or 'notEquals'. 'tryGet' returns null when a path segment is missing;
    /// the comparison may silently produce unexpected results. Wrapping the 'tryGet' in
    /// 'coalesce' with a fallback value gives the comparison a defined operand.
    /// </summary>
    public sealed class UnguardedTryGetInComparedValue : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Unguarded tryGet in Compared Value";
        private const string RuleDescription =
            "The value condition compares the unguarded 'tryGet' expression '{0}' with '{1}'. 'tryGet' can return null when the property is absent. Wrap 'tryGet' in 'coalesce' with a fallback value to define the comparison behavior.";

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
            title: UnguardedTryGetInComparedValue.RuleTitle,
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

            if (expression.Value.Value.Type != JTokenType.String ||
                expression.Value.LanguageExpressions.Length != 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var languageExpression = expression.Value.LanguageExpressions[0];
            if (!string.Equals(expression.Value.Value.ToString(), languageExpression.Expression, StringComparison.Ordinal) ||
                ExpressionsEngine.ParseLanguageExpression(languageExpression.Expression) is not FunctionExpression functionExpression ||
                !string.Equals(functionExpression.Function, "tryGet", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(expression.Value, languageExpression.Expression, expression.Operator.Name),
            };
        }
    }
}
