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
    /// Flags range() calls with arguments known only when the policy is evaluated, outside an if() branch.
    /// </summary>
    public sealed class UnguardedRangeFunction : LinterRule<FunctionCall>
    {
        private const string RuleTitle = "Unguarded Range Function";

        private const string RuleDescription =
            "The expression calls 'range()' with a value that is known only when the policy is evaluated. 'range()' fails when an argument is not an integer or the count is less than 0 or greater than 10000, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the values with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedRangeFunction"/> class.
        /// </summary>
        public UnguardedRangeFunction() : base(
            identifier: "unguarded-range-function",
            category: Category.BestPractices,
            title: UnguardedRangeFunction.RuleTitle,
            descriptionFormat: UnguardedRangeFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(FunctionCall expression, LinterContext context)
        {
            return !expression.IsConditionallyEvaluated &&
                expression.Name.EqualsOrdinalInsensitively("range") &&
                expression.Arguments.Any(argument => argument.IsEvaluationTimeReference())
                ? new[] { this.CreateWarning(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}