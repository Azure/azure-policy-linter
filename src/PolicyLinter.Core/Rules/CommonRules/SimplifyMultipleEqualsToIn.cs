// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Detects anyOf quantifiers containing multiple equals conditions on the same field
    /// that could be simplified to a single in condition.
    /// </summary>
    public sealed class SimplifyMultipleEqualsToIn : LinterRule<Quantifier>
    {
        private const string RuleTitle = "Simplify Multiple Equals to In";

        private const string RuleDescription =
            "The anyOf contains {0} equals conditions on field '{1}' that can be simplified to a single 'in' condition.";

        /// <summary>
        /// Initializes a new instance of the <see cref="SimplifyMultipleEqualsToIn"/> class.
        /// </summary>
        public SimplifyMultipleEqualsToIn() : base(
            identifier: "simplify-multiple-equals-to-in",
            category: Category.BestPractices,
            title: SimplifyMultipleEqualsToIn.RuleTitle,
            descriptionFormat: SimplifyMultipleEqualsToIn.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Quantifier expression, LinterContext context)
        {
            if (expression.AnyOf == null || expression.AnyOf.Value.Length < 2)
            {
                return Array.Empty<LinterOutput>();
            }

            var conditions = expression.AnyOf.Value;

            // Group leaf conditions that use the "equals" operator by their field name.
            var fieldGroups = new Dictionary<string, List<LeafCondition>>(StringComparer.OrdinalIgnoreCase);

            foreach (var condition in conditions)
            {
                if (condition is LeafCondition leaf &&
                    leaf.Field != null &&
                    leaf.Operator != null &&
                    leaf.Operator.Name.EqualsOrdinalInsensitively("equals") &&
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
                .Select(kvp => this.CreateInformational(
                    expression: kvp.Value.First(),
                    kvp.Value.Count,
                    kvp.Key))
                .ToArray();
        }
    }
}
