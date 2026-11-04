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
    /// Flags bool() calls on values known only when the policy is evaluated, outside an if() branch.
    /// </summary>
    public sealed class UnguardedBoolFunction : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Unguarded Bool Function";

        private const string RuleDescription =
            "The expression calls 'bool()' on a value that is known only when the policy is evaluated. 'bool()' fails when the value is not a boolean or the string 'true' or 'false', including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedBoolFunction"/> class.
        /// </summary>
        public UnguardedBoolFunction() : base(
            identifier: "unguarded-bool-function",
            category: Category.BestPractices,
            title: UnguardedBoolFunction.RuleTitle,
            descriptionFormat: UnguardedBoolFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            var fires = expression.FunctionCalls.Any(call =>
                !call.IsConditionallyEvaluated &&
                call.Name.EqualsOrdinalInsensitively("bool") &&
                call.ArgumentDependsOnEvaluationTimeValue(argumentIndex: 0));

            return fires
                ? new[] { this.CreateWarning(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}