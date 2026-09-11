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
    /// Detects policy descriptions that repeat the display name without adding context.
    /// </summary>
    public sealed class DescriptionDuplicatesDisplayName : LinterRule<PolicyDefinitionProperties>
    {
        private const string RuleTitle = "Description Duplicates Display Name";
        private const string RuleDescription = "The description repeats the display name and adds no context. Replace it with a concise explanation of what the policy checks and why.";

        /// <summary>
        /// Initializes a new instance of the <see cref="DescriptionDuplicatesDisplayName"/> class.
        /// </summary>
        public DescriptionDuplicatesDisplayName() : base(
            identifier: "description-duplicates-display-name",
            category: Category.BestPractices,
            title: DescriptionDuplicatesDisplayName.RuleTitle,
            descriptionFormat: DescriptionDuplicatesDisplayName.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyDefinitionProperties expression, LinterContext context)
        {
            if (expression.DisplayName?.Value.Type != JTokenType.String ||
                expression.Description?.Value.Type != JTokenType.String)
            {
                return Array.Empty<LinterOutput>();
            }

            var displayName = expression.DisplayName.Value.ToString().Trim();
            var description = expression.Description.Value.ToString().Trim();

            if (string.IsNullOrEmpty(displayName) ||
                string.IsNullOrEmpty(description) ||
                !string.Equals(displayName, description, StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { this.CreateInformational(expression.Description) };
        }
    }
}
