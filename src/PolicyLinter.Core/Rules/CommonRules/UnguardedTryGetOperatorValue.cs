// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Flags a condition whose operator value is a 'tryGet' expression. 'tryGet' can return null
    /// when its first property is missing, while later property arguments are not safely dereferenced.
    /// </summary>
    public sealed class UnguardedTryGetOperatorValue : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Unguarded tryGet Operator Value";
        private const string RuleDescription =
            "The '{0}' operator's value is a 'tryGet(...)' expression. 'tryGet' can return null when its first property is missing, and later property arguments are not safely dereferenced. A null operator value fails policy evaluation. Make nested lookups safe, then use 'coalesce(..., <fallback>)' with an operator-compatible fallback.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedTryGetOperatorValue"/> class.
        /// </summary>
        public UnguardedTryGetOperatorValue() : base(
            identifier: "unguarded-tryget-operator-value",
            category: Category.BestPractices,
            title: UnguardedTryGetOperatorValue.RuleTitle,
            descriptionFormat: UnguardedTryGetOperatorValue.RuleDescription,
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

            if (expression.Operator.Value.Type != JTokenType.String ||
                expression.Operator.LanguageExpressions.Length != 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var valueExpression = expression.Operator.LanguageExpressions[0];
            if (!string.Equals(expression.Operator.Value.ToString(), valueExpression.Expression, StringComparison.Ordinal) ||
                !valueExpression.TryGetFunctionName(out var functionName) ||
                !string.Equals(functionName, "tryGet", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateError(expression.Operator, expression.Operator.Name),
            };
        }
    }
}
