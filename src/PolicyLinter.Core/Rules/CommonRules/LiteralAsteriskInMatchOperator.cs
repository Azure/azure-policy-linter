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
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Flags match-family operators whose literal string value contains an asterisk.
    /// Match-family operators treat an asterisk as a literal character rather than a wildcard.
    /// </summary>
    public sealed class LiteralAsteriskInMatchOperator : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Literal Asterisk in Match Operator";
        private const string RuleDescription =
            "The condition uses the '{0}' operator with value '{1}'. Match operators treat '*' as a literal character, not a wildcard, so the condition's result depends on a literal asterisk. If wildcard matching was intended, use '{2}'.";

        private static readonly OrdinalInsensitiveHashSet MatchOperators = new OrdinalInsensitiveHashSet
        {
            "match",
            "notMatch",
            "matchInsensitively",
            "notMatchInsensitively",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="LiteralAsteriskInMatchOperator"/> class.
        /// </summary>
        public LiteralAsteriskInMatchOperator() : base(
            identifier: "literal-asterisk-in-match-operator",
            category: Category.BestPractices,
            title: LiteralAsteriskInMatchOperator.RuleTitle,
            descriptionFormat: LiteralAsteriskInMatchOperator.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            if (expression.Operator == null ||
                !LiteralAsteriskInMatchOperator.MatchOperators.Contains(expression.Operator.Name))
            {
                return Array.Empty<LinterOutput>();
            }

            if (!expression.Operator.HasLiteralValue ||
                expression.Operator.Value.Type != JTokenType.String)
            {
                return Array.Empty<LinterOutput>();
            }

            var operandValue = expression.Operator.Value.ToString();
            if (!operandValue.Contains('*', StringComparison.Ordinal))
            {
                return Array.Empty<LinterOutput>();
            }

            var replacement = expression.Operator.Name.StartsWith("not", StringComparison.OrdinalIgnoreCase)
                ? "notLike"
                : "like";

            return new[]
            {
                this.CreateWarning(expression.Operator, expression.Operator.Name, operandValue, replacement),
            };
        }
    }
}
