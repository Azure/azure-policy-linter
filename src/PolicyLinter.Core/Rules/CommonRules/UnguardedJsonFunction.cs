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
    /// Flags json() calls on values known only when the policy is evaluated, outside an if() branch.
    /// </summary>
    public sealed class UnguardedJsonFunction : LinterRule<FunctionCall>
    {
        private const string RuleTitle = "Unguarded Json Function";

        private const string RuleDescription =
            "The expression calls 'json()' on a value that is known only when the policy is evaluated. 'json()' fails when the value is not valid JSON, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedJsonFunction"/> class.
        /// </summary>
        public UnguardedJsonFunction() : base(
            identifier: "unguarded-json-function",
            category: Category.BestPractices,
            title: UnguardedJsonFunction.RuleTitle,
            descriptionFormat: UnguardedJsonFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(FunctionCall expression, LinterContext context)
        {
            return !expression.IsConditionallyEvaluated &&
                expression.Name.EqualsOrdinalInsensitively("json") &&
                expression.Arguments.Any(argument => argument.IsEvaluationTimeReference())
                ? new[] { this.CreateWarning(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}