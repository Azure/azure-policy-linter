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
    /// Flags tryGet() calls with more than one key.
    /// </summary>
    public sealed class TryGetWithMultipleKeys : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "tryGet with Multiple Keys";

        private const string RuleDescription =
            "The expression calls 'tryGet()' with more than one key. Only the first key is looked up safely, and the expression fails when a later key is missing. A failed expression makes the policy deny the request. Use 'selectProperty()', or one 'tryGet()' for each key.";

        /// <summary>
        /// Initializes a new instance of the <see cref="TryGetWithMultipleKeys"/> class.
        /// </summary>
        public TryGetWithMultipleKeys() : base(
            identifier: "tryget-with-multiple-keys",
            category: Category.TemplateFunctions,
            title: TryGetWithMultipleKeys.RuleTitle,
            descriptionFormat: TryGetWithMultipleKeys.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            return expression.Name.EqualsOrdinalInsensitively("tryGet") &&
                expression.Arguments.Length > 2
                ? new[] { this.CreateError(expression) }
                : Array.Empty<LinterOutput>();
        }
    }
}