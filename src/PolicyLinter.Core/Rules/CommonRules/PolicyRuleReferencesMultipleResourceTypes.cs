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
    /// Detects policies whose if condition references more than one resource type,
    /// combining the resource types named in 'type' field conditions with those
    /// resolved from field aliases.
    /// </summary>
    public sealed class PolicyRuleReferencesMultipleResourceTypes : LinterRule<IfCondition>
    {
        private const string RuleDescription =
            "The policy rule references multiple resource types: {0}. Targeting several related types is a valid pattern; if this is unintended, target a single type and group policies with an initiative.";

        /// <summary>
        /// Initializes a new instance of the <see cref="PolicyRuleReferencesMultipleResourceTypes"/> class.
        /// </summary>
        public PolicyRuleReferencesMultipleResourceTypes() : base(
            identifier: "policy-rule-references-multiple-resource-types",
            category: Category.BestPractices,
            title: "Policy Rule References Multiple Resource Types",
            descriptionFormat: PolicyRuleReferencesMultipleResourceTypes.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(IfCondition expression, LinterContext context)
        {
            var referencedResourceTypes = expression.ReferencedResourceTypes;
            if (referencedResourceTypes.Length <= 1)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateInformational(expression: expression, string.Join(", ", referencedResourceTypes)),
            };
        }
    }
}
