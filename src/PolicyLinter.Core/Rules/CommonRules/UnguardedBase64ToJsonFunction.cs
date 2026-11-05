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
    /// Flags base64ToJson() calls on values known only when the policy is evaluated, unless an if() around the call skips it for a missing property.
    /// </summary>
    public sealed class UnguardedBase64ToJsonFunction : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Unguarded base64ToJson Function";

        private const string RuleDescription =
            "The expression calls 'base64ToJson()' on a value that is known only when the policy is evaluated. 'base64ToJson()' fails when the value is not base64-encoded JSON, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedBase64ToJsonFunction"/> class.
        /// </summary>
        public UnguardedBase64ToJsonFunction() : base(
            identifier: "unguarded-base64tojson-function",
            category: Category.TemplateFunctions,
            title: UnguardedBase64ToJsonFunction.RuleTitle,
            descriptionFormat: UnguardedBase64ToJsonFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            return expression.Name.EqualsOrdinalInsensitively("base64ToJson") &&
                expression.Arguments.Any(argument => argument.IsEvaluationTimeReference() && !argument.IsGuardedAgainst(JValue.CreateString(string.Empty)))
                ? new[] { this.CreateWarning(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}