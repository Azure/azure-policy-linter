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
    /// Flags replace() calls whose string to replace is known only when the policy is evaluated, outside an if() branch.
    /// </summary>
    public sealed class UnguardedReplaceFunction : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Unguarded Replace Function";

        private const string RuleDescription =
            "The expression calls 'replace()' with a string to replace that is known only when the policy is evaluated. 'replace()' fails when the string to replace is empty, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedReplaceFunction"/> class.
        /// </summary>
        public UnguardedReplaceFunction() : base(
            identifier: "unguarded-replace-function",
            category: Category.BestPractices,
            title: UnguardedReplaceFunction.RuleTitle,
            descriptionFormat: UnguardedReplaceFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            return !expression.IsConditionallyEvaluated &&
                expression.Name.EqualsOrdinalInsensitively("replace") &&
                expression.Arguments.Length > 1 &&
                expression.Arguments[1].IsEvaluationTimeReference()
                ? new[] { this.CreateWarning(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}