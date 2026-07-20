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
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Flags direct substring calls on resource values when the requested substring
    /// can exceed the resource value's length.
    /// </summary>
    public sealed class UnguardedSubstringOnResourceValue : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Unguarded Substring on Resource Value";

        private const string RuleDescription =
            "The value expression calls 'substring' directly on a resource value. If the value is shorter than the requested substring, policy evaluation fails and the policy acts as deny. Guard the call with 'if()' and 'length()'.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedSubstringOnResourceValue"/> class.
        /// </summary>
        public UnguardedSubstringOnResourceValue() : base(
            identifier: "unguarded-substring-on-resource-value",
            category: Category.BestPractices,
            title: UnguardedSubstringOnResourceValue.RuleTitle,
            descriptionFormat: UnguardedSubstringOnResourceValue.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            if (expression.Value?.Value.Type != JTokenType.String ||
                expression.Value.LanguageExpressions.Length != 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var rawValue = expression.Value.Value.Value<string>();
            if (rawValue == null ||
                !string.Equals(rawValue, expression.Value.LanguageExpressions[0].Expression, StringComparison.Ordinal))
            {
                return Array.Empty<LinterOutput>();
            }

            var languageExpression = ExpressionsEngine.ParseLanguageExpression(rawValue);
            if (languageExpression is not FunctionExpression substring ||
                !string.Equals(substring.Function, "substring", StringComparison.OrdinalIgnoreCase) ||
                substring.Parameters.Length != 3)
            {
                return Array.Empty<LinterOutput>();
            }

            if (!UnguardedSubstringOnResourceValue.ContainsResourceValueReference(substring.Parameters[0]) ||
                !UnguardedSubstringOnResourceValue.TryGetNonnegativeIntegerLiteral(substring.Parameters[1], out var start) ||
                !UnguardedSubstringOnResourceValue.TryGetNonnegativeIntegerLiteral(substring.Parameters[2], out var length) ||
                (start == 0 && length == 0))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateError(expression: expression.Value),
            };
        }

        private static bool ContainsResourceValueReference(LanguageExpression expression)
        {
            if (expression is not FunctionExpression function)
            {
                return false;
            }

            if (string.Equals(function.Function, "field", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(function.Function, "current", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            foreach (var parameter in function.Parameters)
            {
                if (UnguardedSubstringOnResourceValue.ContainsResourceValueReference(parameter))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool TryGetNonnegativeIntegerLiteral(LanguageExpression expression, out long value)
        {
            value = 0;

            if (expression is not JTokenExpression literal ||
                literal.Value.Type != JTokenType.Integer ||
                literal.Value is not JValue tokenValue ||
                tokenValue.Value is not long integerValue ||
                integerValue < 0)
            {
                return false;
            }

            value = integerValue;
            return true;
        }
    }
}
