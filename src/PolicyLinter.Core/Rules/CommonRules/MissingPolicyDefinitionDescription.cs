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
    /// Detects a policy definition with a missing or blank description.
    /// </summary>
    public sealed class MissingPolicyDefinitionDescription : LinterRule<PolicyDefinitionProperties>
    {
        private const string RuleTitle = "Missing Policy Definition Description";
        private const string RuleDescription =
            "The policy definition does not specify a nonblank 'description', so context for when it is used is missing. Add a concise description of what the policy checks and why.";

        /// <summary>
        /// Initializes a new instance of the <see cref="MissingPolicyDefinitionDescription"/> class.
        /// </summary>
        public MissingPolicyDefinitionDescription() : base(
            identifier: "missing-policy-definition-description",
            category: Category.BestPractices,
            title: MissingPolicyDefinitionDescription.RuleTitle,
            descriptionFormat: MissingPolicyDefinitionDescription.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyDefinitionProperties expression, LinterContext context)
        {
            if (expression.Description == null)
            {
                return new[] { this.CreateInformational(expression: expression) };
            }

            if (!string.IsNullOrWhiteSpace(expression.Description.Value.ToString()))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { this.CreateInformational(expression: expression.Description) };
        }
    }
}
