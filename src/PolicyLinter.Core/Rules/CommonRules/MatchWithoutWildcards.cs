// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Flags matchInsensitively/notMatchInsensitively conditions whose
    /// operand contains no wildcards (#, ?, or .). Without wildcards these
    /// operators behave identically to equals/notEquals (both are case-insensitive)
    /// which suggests the author intended pattern matching.
    /// Note: match/notMatch are case-sensitive and have no exact-match equivalent,
    /// so they are not flagged by this rule.
    /// </summary>
    public sealed class MatchWithoutWildcards : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "match/matchInsensitively Without Wildcards";
        private const string RuleDescription =
            "The condition uses the '{0}' operator with value '{1}' which contains no wildcards (#, ?, or .). Use '{2}' instead to better reflect the intention of exact matching.";

        /// <summary>
        /// Initializes a new instance of the <see cref="MatchWithoutWildcards"/> class.
        /// </summary>
        public MatchWithoutWildcards() : base(
            identifier: "match-without-wildcards",
            category: Category.BestPractices,
            title: MatchWithoutWildcards.RuleTitle,
            descriptionFormat: MatchWithoutWildcards.RuleDescription,
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

            // Only flag case-insensitive variants -- they are equivalent to equals/notEquals
            // when no wildcards are present. The case-sensitive match/notMatch have no
            // exact-match equivalent so we cannot suggest a replacement.
            if (!string.Equals(operatorName, "matchInsensitively", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(operatorName, "notMatchInsensitively", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<LinterOutput>();
            }

            if (!expression.Operator.HasLiteralValue)
            {
                return Array.Empty<LinterOutput>();
            }

            var operandValue = expression.Operator.Value.ToString();

            if (operandValue.Contains('#', StringComparison.Ordinal) ||
                operandValue.Contains('?', StringComparison.Ordinal) ||
                operandValue.Contains('.', StringComparison.Ordinal))
            {
                return Array.Empty<LinterOutput>();
            }

            var replacement = string.Equals(operatorName, "matchInsensitively", StringComparison.OrdinalIgnoreCase)
                ? "equals"
                : "notEquals";

            return new[]
            {
                this.CreateWarning(expression.Operator, operatorName, operandValue, replacement)
            };
        }
    }
}
