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
    /// Flags float() calls on values known only when the policy is evaluated, unless an if() around the call skips it for a missing property.
    /// </summary>
    public sealed class UnguardedFloatFunction : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Unguarded Float Function";

        private const string RuleDescription =
            "The expression calls 'float()' on a value that is known only when the policy is evaluated. 'float()' fails when the value is not a number, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedFloatFunction"/> class.
        /// </summary>
        public UnguardedFloatFunction() : base(
            identifier: "unguarded-float-function",
            category: Category.TemplateFunctions,
            title: UnguardedFloatFunction.RuleTitle,
            descriptionFormat: UnguardedFloatFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            return expression.Name.EqualsOrdinalInsensitively("float") &&
                expression.Arguments.Any(argument => argument.IsEvaluationTimeReference() && !argument.IsGuardedAgainst(JValue.CreateString(string.Empty)))
                ? new[] { this.CreateWarning(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}