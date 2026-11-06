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
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Flags substring() calls on values known only when the policy is evaluated.
    /// </summary>
    public sealed class UnguardedSubstringFunction : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Unguarded Substring Function";

        private const string RuleDescription =
            "The expression calls 'substring()' with a value that is known only when the policy is evaluated. When the requested range runs past the end of the input the expression fails, and a failed expression makes the policy deny the request. Use 'take()' and 'skip()' instead; they don't fail on short values.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedSubstringFunction"/> class.
        /// </summary>
        public UnguardedSubstringFunction() : base(
            identifier: "unguarded-substring-function",
            category: Category.TemplateFunctions,
            title: UnguardedSubstringFunction.RuleTitle,
            descriptionFormat: UnguardedSubstringFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            if (expression.Name.EqualsOrdinalInsensitively("substring") &&
                expression.Arguments.Any(argument => argument.IsEvaluationTimeReference()))
            {
                return new[] { this.CreateWarning(expression) };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
