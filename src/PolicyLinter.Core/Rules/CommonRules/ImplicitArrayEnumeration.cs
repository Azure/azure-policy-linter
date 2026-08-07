// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Identifies field conditions that implicitly enumerate an array alias.
    /// </summary>
    public sealed class ImplicitArrayEnumeration : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Implicit Array Enumeration";

        private const string RuleDescription =
            "The condition targets the members of array alias '{0}', which performs an implicit 'allOf' evaluation over the array. Use a field count expression instead.";

        /// <summary>
        /// Initializes a new instance of the <see cref="ImplicitArrayEnumeration"/> class.
        /// </summary>
        public ImplicitArrayEnumeration() : base(
            identifier: "implicit-array-enumeration",
            category: Category.BestPractices,
            title: ImplicitArrayEnumeration.RuleTitle,
            descriptionFormat: ImplicitArrayEnumeration.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var reference = expression.Field?.FieldAccessorReference;

            if (reference?.IsResolved != true ||
                !FieldPathHelper.IsArrayAlias(reference.Identifier) ||
                expression.Operator == null ||
                string.Equals(expression.Operator.Name, "exists", StringComparison.OrdinalIgnoreCase) ||
                ImplicitArrayEnumeration.IsFullyReducedByCountScope(reference))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateInformational(expression.Field, reference.Identifier),
            };
        }

        private static bool IsFullyReducedByCountScope(Reference reference)
        {
            var scope = reference.ReferencedCountExpressionScope;
            return scope?.Type == CountScopeType.Field &&
                ImplicitArrayEnumeration.CountArraySelectors(reference.Identifier) ==
                ImplicitArrayEnumeration.CountArraySelectors(scope.Identifier);
        }

        private static int CountArraySelectors(string alias)
        {
            var count = 0;
            var index = 0;

            while ((index = alias.IndexOf("[*]", index, StringComparison.Ordinal)) >= 0)
            {
                count++;
                index += 3;
            }

            return count;
        }
    }
}
