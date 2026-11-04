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
    /// Flags div() or mod() calls that fail for a literal value or a known parameter value.
    /// </summary>
    public sealed class InvalidDivOrModFunctionArgument : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Invalid Div or Mod Function Argument";

        private const string RuleDescription =
            "The call {0} fails when the policy is evaluated, because an argument is not an integer or the divisor is zero. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidDivOrModFunctionArgument"/> class.
        /// </summary>
        public InvalidDivOrModFunctionArgument() : base(
            identifier: "invalid-div-or-mod-function-argument",
            category: Category.BestPractices,
            title: InvalidDivOrModFunctionArgument.RuleTitle,
            descriptionFormat: InvalidDivOrModFunctionArgument.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            return expression.FunctionCalls
                .Where(call => !call.IsConditionallyEvaluated && (call.Name.EqualsOrdinalInsensitively("div") || call.Name.EqualsOrdinalInsensitively("mod")))
                .SelectMany(call => call.GetFailuresForKnownValues(context))
                .Select(failure => this.CreateError(expression, failure))
                .ToArray();
        }
    }
}