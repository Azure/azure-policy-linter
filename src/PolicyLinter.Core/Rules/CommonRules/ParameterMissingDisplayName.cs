// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects a policy parameter that has no <c>metadata.displayName</c>. The definition is valid,
    /// but the portal assignment experience shows the raw parameter name instead of a friendly label.
    /// </summary>
    public sealed class ParameterMissingDisplayName : LinterRule<Parameter>
    {
        private const string RuleTitle = "Parameter Missing Display Name";
        private const string RuleDescription = "The parameter '{0}' has no 'metadata.displayName'. Without one, whoever assigns the policy sees the raw parameter name instead of a friendly label. Add a 'metadata.displayName'.";

        /// <summary>
        /// Initializes a new instance of the <see cref="ParameterMissingDisplayName"/> class.
        /// </summary>
        public ParameterMissingDisplayName() : base(
            identifier: "parameter-missing-display-name",
            category: Category.BestPractices,
            title: ParameterMissingDisplayName.RuleTitle,
            descriptionFormat: ParameterMissingDisplayName.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Parameter expression, LinterContext context)
        {
            var displayNameToken = (expression.Metadata as JObject)?.GetValue("displayName", StringComparison.OrdinalIgnoreCase);

            if (displayNameToken != null && displayNameToken.Type != JTokenType.String)
            {
                return Array.Empty<LinterOutput>();
            }

            var displayName = displayNameToken?.Value<string>();

            if (!string.IsNullOrWhiteSpace(displayName))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { this.CreateInformational(expression: expression, expression.Name) };
        }
    }
}
