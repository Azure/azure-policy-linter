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
        private const string RuleDescription = "The parameter '{0}' has no 'displayName' in its metadata, so the portal shows the raw parameter name during assignment. Add a 'metadata.displayName' to give it a friendly label.";

        /// <summary>
        /// Initializes a new instance of the <see cref="ParameterMissingDisplayName"/> class.
        /// </summary>
        public ParameterMissingDisplayName() : base(
            identifier: "parameter-missing-display-name",
            category: Category.Misc,
            title: ParameterMissingDisplayName.RuleTitle,
            descriptionFormat: ParameterMissingDisplayName.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Parameter expression, LinterContext context)
        {
            var displayName = (expression.Metadata as JObject)?["displayName"]?.Value<string>();
            if (!string.IsNullOrWhiteSpace(displayName))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { this.CreateInformational(expression: expression, expression.Name) };
        }
    }
}
