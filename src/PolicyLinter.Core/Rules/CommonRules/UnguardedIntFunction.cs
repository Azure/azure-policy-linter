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
    /// Flags int() calls on values known only when the policy is evaluated, unless an if() condition around the call uses the same value.
    /// </summary>
    public sealed class UnguardedIntFunction : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Unguarded Int Function";

        private const string RuleDescription =
            "The expression calls 'int()' on a value that is known only when the policy is evaluated. 'int()' fails when the value is not an integer, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedIntFunction"/> class.
        /// </summary>
        public UnguardedIntFunction() : base(
            identifier: "unguarded-int-function",
            category: Category.TemplateFunctions,
            title: UnguardedIntFunction.RuleTitle,
            descriptionFormat: UnguardedIntFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            return expression.Name.EqualsOrdinalInsensitively("int") &&
                expression.Arguments.Any(argument => argument.IsEvaluationTimeReference() && !argument.IsCheckedByGuardCondition())
                ? new[] { this.CreateWarning(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}