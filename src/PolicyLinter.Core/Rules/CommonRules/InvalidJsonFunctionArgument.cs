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
    /// Flags json() calls that fail for a literal value or a known parameter value.
    /// </summary>
    public sealed class InvalidJsonFunctionArgument : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Invalid Json Function Argument";

        private const string RuleDescription =
            "The call {0} fails when the policy is evaluated, because the value is not valid JSON. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidJsonFunctionArgument"/> class.
        /// </summary>
        public InvalidJsonFunctionArgument() : base(
            identifier: "invalid-json-function-argument",
            category: Category.BestPractices,
            title: InvalidJsonFunctionArgument.RuleTitle,
            descriptionFormat: InvalidJsonFunctionArgument.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            return expression.FunctionCalls
                .Where(call => !call.IsConditionallyEvaluated && call.Name.EqualsOrdinalInsensitively("json"))
                .SelectMany(call => call.GetFailuresForKnownValues(context))
                .Select(failure => this.CreateError(expression, failure))
                .ToArray();
        }
    }
}