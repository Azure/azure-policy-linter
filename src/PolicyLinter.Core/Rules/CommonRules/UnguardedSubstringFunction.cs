// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Flags substring calls on non-literal values that are not guarded against an input
    /// shorter than the requested range.
    /// </summary>
    public sealed class UnguardedSubstringFunction : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Unguarded Substring Function";

        private const string RuleDescription =
            "The expression calls 'substring' on a value that is not a literal, without checking its length first. When the value is shorter than the requested range the expression fails, and a failed expression makes the policy deny the request. Guard the call with 'if()' and 'length()'.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedSubstringFunction"/> class.
        /// </summary>
        public UnguardedSubstringFunction() : base(
            identifier: "unguarded-substring-function",
            category: Category.BestPractices,
            title: UnguardedSubstringFunction.RuleTitle,
            descriptionFormat: UnguardedSubstringFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            if (expression.Expression.StartsWith("[substring(", StringComparison.OrdinalIgnoreCase) &&
                expression.References.Any())
            {
                return new[] { this.CreateError(expression: expression) };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
