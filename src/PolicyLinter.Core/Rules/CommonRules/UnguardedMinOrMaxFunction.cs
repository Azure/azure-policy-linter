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
    /// Flags min() and max() calls with arguments known only when the policy is evaluated, outside an if() branch.
    /// </summary>
    public sealed class UnguardedMinOrMaxFunction : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Unguarded Min or Max Function";

        private const string RuleDescription =
            "The expression calls '{0}()' with a value that is known only when the policy is evaluated. '{0}()' fails when the array is empty or a value is not a number, including the empty array or string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedMinOrMaxFunction"/> class.
        /// </summary>
        public UnguardedMinOrMaxFunction() : base(
            identifier: "unguarded-min-or-max-function",
            category: Category.BestPractices,
            title: UnguardedMinOrMaxFunction.RuleTitle,
            descriptionFormat: UnguardedMinOrMaxFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            var call = expression.FunctionCalls.FirstOrDefault(call =>
                !call.IsConditionallyEvaluated &&
                (call.Name.EqualsOrdinalInsensitively("min") || call.Name.EqualsOrdinalInsensitively("max")) &&
                call.Arguments.Any(argument => argument.DependsOnEvaluationTimeValue));

            return call == null
                ? Array.Empty<LinterOutput>()
                : new[] { this.CreateWarning(expression, call.Name) };
        }
    }
}