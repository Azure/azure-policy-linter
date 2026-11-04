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
    /// Flags min() or max() calls that fail for a literal value or a known parameter value.
    /// </summary>
    public sealed class InvalidMinOrMaxFunctionArgument : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Invalid Min or Max Function Argument";

        private const string RuleDescription =
            "The call {0} fails when the policy is evaluated, because the array is empty or a value is not a number. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidMinOrMaxFunctionArgument"/> class.
        /// </summary>
        public InvalidMinOrMaxFunctionArgument() : base(
            identifier: "invalid-min-or-max-function-argument",
            category: Category.BestPractices,
            title: InvalidMinOrMaxFunctionArgument.RuleTitle,
            descriptionFormat: InvalidMinOrMaxFunctionArgument.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            return expression.FunctionCalls
                .Where(call => !call.IsConditionallyEvaluated && (call.Name.EqualsOrdinalInsensitively("min") || call.Name.EqualsOrdinalInsensitively("max")))
                .SelectMany(call => call.GetFailuresForKnownValues(context))
                .Select(failure => this.CreateError(expression, failure))
                .ToArray();
        }
    }
}