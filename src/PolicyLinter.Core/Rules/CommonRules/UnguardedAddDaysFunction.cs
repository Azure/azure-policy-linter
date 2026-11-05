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
    /// Flags addDays() calls with arguments known only when the policy is evaluated. The finding is a warning,
    /// or informational when the call is in an if() branch, because the if() condition might check the value.
    /// </summary>
    public sealed class UnguardedAddDaysFunction : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Unguarded addDays Function";

        private const string RuleDescription =
            "The expression calls 'addDays()' with a value that is known only when the policy is evaluated. 'addDays()' fails when the date is not in ISO 8601 format or the number of days is not an integer, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the values with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedAddDaysFunction"/> class.
        /// </summary>
        public UnguardedAddDaysFunction() : base(
            identifier: "unguarded-adddays-function",
            category: Category.TemplateFunctions,
            title: UnguardedAddDaysFunction.RuleTitle,
            descriptionFormat: UnguardedAddDaysFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            if (!expression.Name.EqualsOrdinalInsensitively("addDays") ||
                !expression.Arguments.Any(argument => argument.IsEvaluationTimeReference()))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { expression.IsConditionallyEvaluated ? this.CreateInformational(expression) : this.CreateWarning(expression) };
        }
    }
}
