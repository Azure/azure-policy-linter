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
    public sealed class UnguardedIpRangeContainsFunction : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Unguarded ipRangeContains Function";

        private const string RuleDescription =
            "The expression calls 'ipRangeContains()' with a value that is known only when the policy is evaluated. 'ipRangeContains()' fails when a value is not an IP address or range, for example '*', a service tag, or the empty string returned for a missing property. A failed expression makes the policy deny the request. Make sure only IP values reach the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedIpRangeContainsFunction"/> class.
        /// </summary>
        public UnguardedIpRangeContainsFunction() : base(
            identifier: "unguarded-iprangecontains-function",
            category: Category.TemplateFunctions,
            title: UnguardedIpRangeContainsFunction.RuleTitle,
            descriptionFormat: UnguardedIpRangeContainsFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            return !expression.IsConditionallyEvaluated &&
                expression.Name.EqualsOrdinalInsensitively("ipRangeContains") &&
                expression.Arguments.Any(argument => argument.IsEvaluationTimeReference())
                ? new[] { this.CreateWarning(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}