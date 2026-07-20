// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Detects a policy definition with a missing or blank display name.
    /// </summary>
    public sealed class MissingPolicyDefinitionDisplayName : LinterRule<PolicyDefinitionProperties>
    {
        private const string RuleTitle = "Missing Policy Definition Display Name";
        private const string RuleDescription =
            "The policy definition does not specify a nonblank 'displayName'. Add a concise display name that identifies the definition and distinguishes it from other policies.";

        /// <summary>
        /// Initializes a new instance of the <see cref="MissingPolicyDefinitionDisplayName"/> class.
        /// </summary>
        public MissingPolicyDefinitionDisplayName() : base(
            identifier: "missing-policy-definition-display-name",
            category: Category.BestPractices,
            title: MissingPolicyDefinitionDisplayName.RuleTitle,
            descriptionFormat: MissingPolicyDefinitionDisplayName.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyDefinitionProperties expression, LinterContext context)
        {
            if (expression.DisplayName == null)
            {
                return new[] { this.CreateInformational(expression: expression) };
            }

            if (!string.IsNullOrWhiteSpace(expression.DisplayName.Value.ToString()))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { this.CreateInformational(expression: expression.DisplayName) };
        }
    }
}
