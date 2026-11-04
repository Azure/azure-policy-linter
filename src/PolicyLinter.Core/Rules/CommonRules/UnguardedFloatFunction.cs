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
    /// Flags float() calls on values known only when the policy is evaluated, outside an if() branch.
    /// </summary>
    public sealed class UnguardedFloatFunction : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Unguarded Float Function";

        private const string RuleDescription =
            "The expression calls 'float()' on a value that is known only when the policy is evaluated. 'float()' fails when the value is not a number, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedFloatFunction"/> class.
        /// </summary>
        public UnguardedFloatFunction() : base(
            identifier: "unguarded-float-function",
            category: Category.BestPractices,
            title: UnguardedFloatFunction.RuleTitle,
            descriptionFormat: UnguardedFloatFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            var call = expression.FunctionCalls.FirstOrDefault(call =>
                !call.IsConditionallyEvaluated &&
                call.Name.EqualsOrdinalInsensitively("float") &&
                call.ArgumentDependsOnEvaluationTimeValue(argumentIndex: 0));

            return call == null
                ? Array.Empty<LinterOutput>()
                : new[] { this.CreateWarning(expression) };
        }
    }
}