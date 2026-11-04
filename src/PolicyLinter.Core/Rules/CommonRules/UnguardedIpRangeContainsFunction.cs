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
    /// Flags ipRangeContains() calls with arguments known only when the policy is evaluated, outside an if() branch.
    /// </summary>
    public sealed class UnguardedIpRangeContainsFunction : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Unguarded ipRangeContains Function";

        private const string RuleDescription =
            "The expression calls 'ipRangeContains()' with a value that is known only when the policy is evaluated. 'ipRangeContains()' fails when a value is not an IP address or range, for example '*', a service tag, or the empty string returned for a missing property. A failed expression makes the policy deny the request. Make sure only IP values reach the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedIpRangeContainsFunction"/> class.
        /// </summary>
        public UnguardedIpRangeContainsFunction() : base(
            identifier: "unguarded-iprangecontains-function",
            category: Category.BestPractices,
            title: UnguardedIpRangeContainsFunction.RuleTitle,
            descriptionFormat: UnguardedIpRangeContainsFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            var call = expression.FunctionCalls.FirstOrDefault(call =>
                !call.IsConditionallyEvaluated &&
                call.Name.EqualsOrdinalInsensitively("ipRangeContains") &&
                (call.ArgumentDependsOnEvaluationTimeValue(argumentIndex: 0) || call.ArgumentDependsOnEvaluationTimeValue(argumentIndex: 1)));

            return call == null
                ? Array.Empty<LinterOutput>()
                : new[] { this.CreateWarning(expression) };
        }
    }
}