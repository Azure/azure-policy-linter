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
    /// Flags padLeft() calls that fail for a literal value or a known parameter value.
    /// </summary>
    public sealed class InvalidPadLeftFunctionArgument : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Invalid padLeft Function Argument";

        private const string RuleDescription =
            "The call {0} fails when the policy is evaluated, because the total length is not from 1 to 16 or the padding character is not a single character. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidPadLeftFunctionArgument"/> class.
        /// </summary>
        public InvalidPadLeftFunctionArgument() : base(
            identifier: "invalid-padleft-function-argument",
            category: Category.BestPractices,
            title: InvalidPadLeftFunctionArgument.RuleTitle,
            descriptionFormat: InvalidPadLeftFunctionArgument.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            return expression.FunctionCalls
                .Where(call => !call.IsConditionallyEvaluated && call.Name.EqualsOrdinalInsensitively("padLeft"))
                .SelectMany(call => call.GetFailuresForKnownValues(context))
                .Select(failure => this.CreateError(expression, failure))
                .ToArray();
        }
    }
}