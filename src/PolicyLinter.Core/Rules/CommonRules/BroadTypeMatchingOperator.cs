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
    /// Flags a 'type' field condition that uses a broad matching operator
    /// ('like', 'match', 'matchInsensitively', or 'contains') instead of
    /// 'equals' or 'in'. A broad operator can match resource types the author
    /// did not intend to target.
    /// </summary>
    public sealed class BroadTypeMatchingOperator : LinterRule<LeafCondition>
    {
        private const string RuleDescription =
            "The 'type' field is compared with the broad '{0}' operator, which can match resource types you did not intend to target. Use 'equals' or 'in' to target resource types explicitly.";

        private static readonly OrdinalInsensitiveHashSet BroadOperators = new OrdinalInsensitiveHashSet
        {
            "like",
            "match",
            "matchInsensitively",
            "contains",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="BroadTypeMatchingOperator"/> class.
        /// </summary>
        public BroadTypeMatchingOperator() : base(
            identifier: "broad-type-matching-operator",
            category: Category.BestPractices,
            title: "Broad Type Matching Operator",
            descriptionFormat: BroadTypeMatchingOperator.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var fieldName = expression.Field?.FieldAccessorReference?.Identifier;
            if (!string.Equals(fieldName, "type", StringComparison.OrdinalIgnoreCase) ||
                expression.Operator == null)
            {
                return Array.Empty<LinterOutput>();
            }

            if (!BroadTypeMatchingOperator.BroadOperators.Contains(expression.Operator.Name))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(expression.Operator, expression.Operator.Name),
            };
        }
    }
}
