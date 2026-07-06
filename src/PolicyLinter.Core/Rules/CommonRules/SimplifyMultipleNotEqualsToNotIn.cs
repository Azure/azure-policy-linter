// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Detects allOf quantifiers containing multiple notEquals conditions on the same field
    /// that could be simplified to a single notIn condition.
    /// </summary>
    public sealed class SimplifyMultipleNotEqualsToNotIn : LinterRule<Quantifier>
    {
        private const string RuleTitle = "Simplify multiple notEquals to notIn";

        private const string RuleDescription =
            "The allOf contains {0} notEquals conditions on field \"{1}\" that can be simplified to a single \"notIn\" condition.";

        /// <summary>
        /// Initializes a new instance of the <see cref="SimplifyMultipleNotEqualsToNotIn"/> class.
        /// </summary>
        public SimplifyMultipleNotEqualsToNotIn() : base(
            identifier: "simplify-multiple-notequals-to-notin",
            category: Category.BestPractices,
            title: SimplifyMultipleNotEqualsToNotIn.RuleTitle,
            descriptionFormat: SimplifyMultipleNotEqualsToNotIn.RuleDescription,
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

            // Group leaf conditions that use the "notEquals" operator by their field name.
            var fieldGroups = new Dictionary<string, List<LeafCondition>>(StringComparer.OrdinalIgnoreCase);

            foreach (var condition in conditions)
            {
                if (condition is LeafCondition leaf &&
                    leaf.Field != null &&
                    leaf.Operator != null &&
                    string.Equals(leaf.Operator.Name, "notEquals", StringComparison.OrdinalIgnoreCase) &&
                    leaf.Field.HasLiteralValue)
                {
                    var fieldName = leaf.Field.Value.ToString();

                    if (!fieldGroups.TryGetValue(fieldName, out var group))
                    {
                        group = new List<LeafCondition>();
                        fieldGroups[fieldName] = group;
                    }

                    group.Add(leaf);
                }
            }

            return fieldGroups
                .Where(kvp => kvp.Value.Count >= 2)
                .Select(kvp => this.CreateWarning(
                    expression: kvp.Value.First(),
                    kvp.Value.Count,
                    kvp.Key))
                .ToArray();
        }
    }
}
