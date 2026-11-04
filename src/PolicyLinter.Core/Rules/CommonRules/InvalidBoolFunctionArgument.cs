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
    /// Flags bool() calls that fail for a literal value or a known parameter value.
    /// </summary>
    public sealed class InvalidBoolFunctionArgument : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Invalid Bool Function Argument";

        private const string RuleDescription =
            "The call {0} fails when the policy is evaluated, because the value is not a boolean. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidBoolFunctionArgument"/> class.
        /// </summary>
        public InvalidBoolFunctionArgument() : base(
            identifier: "invalid-bool-function-argument",
            category: Category.BestPractices,
            title: InvalidBoolFunctionArgument.RuleTitle,
            descriptionFormat: InvalidBoolFunctionArgument.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            return expression.FunctionCalls
                .Where(call => !call.IsConditionallyEvaluated && call.Name.EqualsOrdinalInsensitively("bool"))
                .SelectMany(call => call.GetFailuresForKnownValues(context))
                .Select(failure => this.CreateError(expression, failure))
                .ToArray();
        }
    }
}