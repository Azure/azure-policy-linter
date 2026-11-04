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
    /// Flags div() and mod() calls with arguments known only when the policy is evaluated, outside an if() branch.
    /// </summary>
    public sealed class UnguardedDivOrModFunction : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Unguarded Div or Mod Function";

        private const string RuleDescription =
            "The expression calls '{0}()' with a value that is known only when the policy is evaluated. '{0}()' fails when an argument is not an integer or the divisor is zero, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the values with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedDivOrModFunction"/> class.
        /// </summary>
        public UnguardedDivOrModFunction() : base(
            identifier: "unguarded-div-or-mod-function",
            category: Category.BestPractices,
            title: UnguardedDivOrModFunction.RuleTitle,
            descriptionFormat: UnguardedDivOrModFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            var call = expression.FunctionCalls.FirstOrDefault(call =>
                !call.IsConditionallyEvaluated &&
                (call.Name.EqualsOrdinalInsensitively("div") || call.Name.EqualsOrdinalInsensitively("mod")) &&
                call.Arguments.Any(argument => argument.IsEvaluationTimeValue));

            return call == null
                ? Array.Empty<LinterOutput>()
                : new[] { this.CreateWarning(expression, call.Name) };
        }
    }
}