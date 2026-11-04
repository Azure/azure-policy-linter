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
    /// Flags substring() calls on values known only when the policy is evaluated, outside an if() branch.
    /// </summary>
    public sealed class UnguardedSubstringFunction : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Unguarded Substring Function";

        private const string RuleDescription =
            "The expression calls 'substring' on a value that is known only when the policy is evaluated, without checking its length first. When the value is shorter than the requested range the expression fails, and a failed expression makes the policy deny the request. Guard the call with 'if()' and 'length()'.";

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
            var fires = expression.FunctionCalls.Any(call =>
                !call.IsConditionallyEvaluated &&
                call.Name.EqualsOrdinalInsensitively("substring") &&
                call.Arguments.Any(argument => argument.DependsOnEvaluationTimeValue));

            return fires
                ? new[] { this.CreateError(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}
