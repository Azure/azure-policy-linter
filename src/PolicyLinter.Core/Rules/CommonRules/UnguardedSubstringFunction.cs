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
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Flags substring() calls on values known only when the policy is evaluated, unless an if() around the call skips it for a missing property.
    /// </summary>
    public sealed class UnguardedSubstringFunction : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Unguarded Substring Function";

        private const string RuleDescription =
            "The expression calls 'substring' on a value that is known only when the policy is evaluated, without checking its length first. When the value is shorter than the requested range the expression fails, and a failed expression makes the policy deny the request. Guard the call with 'if()' and 'length()'.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedSubstringFunction"/> class.
        /// </summary>
        public UnguardedSubstringFunction() : base(
            identifier: "unguarded-substring-function",
            category: Category.TemplateFunctions,
            title: UnguardedSubstringFunction.RuleTitle,
            descriptionFormat: UnguardedSubstringFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            return expression.Name.EqualsOrdinalInsensitively("substring") &&
                expression.Arguments.Any(argument => argument.IsEvaluationTimeReference() && !argument.IsGuardedAgainst(JValue.CreateString(string.Empty)))
                ? new[] { this.CreateError(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}
