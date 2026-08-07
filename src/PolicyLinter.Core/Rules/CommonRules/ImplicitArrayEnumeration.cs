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
            var fieldAccessor = expression.Field?.FieldAccessorReference;

            if (fieldAccessor != null &&
                fieldAccessor.IsResolved == true &&
                FieldPathHelper.IsArrayAlias(fieldAccessor.Identifier) &&
                fieldAccessor.ReferencedCountExpressionScope == null)
            {
                return new[]
                {
                    this.CreateInformational(expression.Field, fieldAccessor.Identifier),
                };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
