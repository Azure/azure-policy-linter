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

    /// <summary>
    /// Flags template function calls that fail for a literal value or a known parameter value.
    /// </summary>
    public sealed class InvalidTemplateFunctionArgument : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Invalid Template Function Argument";

        private const string RuleDescription =
            "The call {0} fails when the policy is evaluated. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidTemplateFunctionArgument"/> class.
        /// </summary>
        public InvalidTemplateFunctionArgument() : base(
            identifier: "invalid-template-function-argument",
            category: Category.BestPractices,
            title: InvalidTemplateFunctionArgument.RuleTitle,
            descriptionFormat: InvalidTemplateFunctionArgument.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            if (expression.IsConditionallyEvaluated)
            {
                return Array.Empty<LinterOutput>();
            }

            return expression
                .GetFailuresForKnownValues(context)
                .Select(failure => this.CreateError(expression, failure))
                .ToArray();
        }
    }
}
