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
    /// Ensures that type conditions appear first in allOf arrays for readability and consistency.
    /// By convention, the type check should be the first condition in an allOf so that readers
    /// immediately see which resource type the policy targets.
    /// </summary>
    public sealed class TypeConditionFirstInAllOf : LinterRule<Quantifier>
    {
        private const string RuleTitle = "Type condition should be first in allOf";

        private const string RuleDescription =
            "The type condition at index {0} should be moved to the first position " +
            "in the allOf for readability, so that readers immediately see which " +
            "resource type the policy targets.";

        /// <summary>
        /// Initializes a new instance of the <see cref="TypeConditionFirstInAllOf"/> class.
        /// </summary>
        public TypeConditionFirstInAllOf() : base(
            identifier: "type-condition-first-in-allof",
            category: Category.BestPractices,
            title: TypeConditionFirstInAllOf.RuleTitle,
            descriptionFormat: TypeConditionFirstInAllOf.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Quantifier expression, LinterContext context)
        {
            if (expression.AllOf == null || expression.AllOf.Value.Length < 2)
            {
                return Array.Empty<LinterOutput>();
            }

            var conditions = expression.AllOf.Value;

            // Already optimal: first condition is a type check
            if (TypeConditionFirstInAllOf.IsTypeCondition(conditions[0]))
            {
                return Array.Empty<LinterOutput>();
            }

            // Find the first type condition at a non-zero index
            for (int i = 1; i < conditions.Length; i++)
            {
                if (TypeConditionFirstInAllOf.IsTypeCondition(conditions[i]))
                {
                    return new[] { this.CreateWarning(expression: conditions[i], i) };
                }
            }

            return Array.Empty<LinterOutput>();
        }

        /// <summary>
        /// Checks whether a condition is a leaf condition that checks the "type" field.
        /// </summary>
        private static bool IsTypeCondition(Condition condition)
        {
            return condition is LeafCondition leaf &&
                leaf.Field != null &&
                string.Equals(leaf.Field.Value?.ToString(), "type", StringComparison.OrdinalIgnoreCase);
        }
    }
}
