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
    /// Detects a 'value' condition that uses a 'tryGet' expression with an operator that coerces
    /// null to an empty string before evaluating the condition.
    /// </summary>
    public sealed class TryGetUseWithNullCoercingOperator : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "tryGet Use with Null-Coercing Operator";
        private const string RuleDescription =
            "The value condition compares the 'tryGet' expression '{0}' with '{1}'. When 'tryGet' returns null, the operator coerces it to an empty string before evaluating the condition.";

        private static readonly OrdinalInsensitiveHashSet NullCoercingOperators = new OrdinalInsensitiveHashSet
        {
            "equals",
            "notEquals",
            "in",
            "notIn",
            "like",
            "notLike",
            "contains",
            "notContains",
            "match",
            "notMatch",
            "matchInsensitively",
            "notMatchInsensitively",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="TryGetUseWithNullCoercingOperator"/> class.
        /// </summary>
        public TryGetUseWithNullCoercingOperator() : base(
            identifier: "tryget-use-with-null-coercing-operator",
            category: Category.BestPractices,
            title: TryGetUseWithNullCoercingOperator.RuleTitle,
            descriptionFormat: TryGetUseWithNullCoercingOperator.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            if (expression.Value == null ||
                expression.Operator == null ||
                !TryGetUseWithNullCoercingOperator.NullCoercingOperators.Contains(expression.Operator.Name))
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
                this.CreateInformational(expression.Value, languageExpression.Expression, expression.Operator.Name),
            };
        }
    }
}
