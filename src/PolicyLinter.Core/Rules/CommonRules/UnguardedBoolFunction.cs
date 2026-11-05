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
    /// Flags bool() calls on values known only when the policy is evaluated, unless an if() around the call skips it for a missing property.
    /// </summary>
    public sealed class UnguardedBoolFunction : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Unguarded Bool Function";

        private const string RuleDescription =
            "The expression calls 'bool()' on a value that is known only when the policy is evaluated. 'bool()' fails when the value is not a boolean or the string 'true' or 'false', including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedBoolFunction"/> class.
        /// </summary>
        public UnguardedBoolFunction() : base(
            identifier: "unguarded-bool-function",
            category: Category.TemplateFunctions,
            title: UnguardedBoolFunction.RuleTitle,
            descriptionFormat: UnguardedBoolFunction.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            return expression.Name.EqualsOrdinalInsensitively("bool") &&
                expression.Arguments.Any(argument => argument.IsEvaluationTimeReference() && !argument.IsGuardedAgainst(JValue.CreateString(string.Empty)))
                ? new[] { this.CreateWarning(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}