// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System;

    /// <summary>
    /// Detects allOf or anyOf quantifiers that contain only a single child expression,
    /// which can be replaced by the child expression directly.
    /// </summary>
    public sealed class UnnecessaryQuantifierWrapper : LinterRule<Quantifier>
    {
        private const string RuleTitle = "Unnecessary allOf/anyOf wrapper";

        private const string RuleDescription =
            "The \"{0}\" contains a single expression and can be removed. Use the inner expression directly.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnnecessaryQuantifierWrapper"/> class.
        /// </summary>
        public UnnecessaryQuantifierWrapper() : base(
            identifier: "unnecessary-quantifier-wrapper",
            category: Category.BestPractices,
            title: UnnecessaryQuantifierWrapper.RuleTitle,
            descriptionFormat: UnnecessaryQuantifierWrapper.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Quantifier expression, LinterContext context)
        {
            if (expression.AllOf != null && expression.AllOf.Value.Length == 1)
            {
                return new[] { this.CreateWarning(expression: expression, "allOf") };
            }

            if (expression.AnyOf != null && expression.AnyOf.Value.Length == 1)
            {
                return new[] { this.CreateWarning(expression: expression, "anyOf") };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
