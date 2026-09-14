// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Detects All-mode policies whose referenced resource types all support Indexed mode.
    /// </summary>
    public sealed class AllModeWithIndexableResourceTypes : LinterRule<PolicyDefinitionProperties>
    {
        private const string RuleTitle = "All Mode With Indexable Resource Types";
        private const string RuleDescription =
            "The policy mode is 'All', and every referenced resource type supports tags and location. Consider 'Indexed' mode to restrict evaluation to resource types with those capabilities.";

        /// <summary>
        /// Initializes a new instance of the <see cref="AllModeWithIndexableResourceTypes"/> class.
        /// </summary>
        public AllModeWithIndexableResourceTypes() : base(
            identifier: "all-mode-with-indexable-resource-types",
            category: Category.BestPractices,
            title: AllModeWithIndexableResourceTypes.RuleTitle,
            descriptionFormat: AllModeWithIndexableResourceTypes.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyDefinitionProperties expression, LinterContext context)
        {
            var mode = expression.Mode;
            if (mode == null || !mode.HasLiteralValue || !mode.Value.ToString().EqualsOrdinalInsensitively("All"))
            {
                return Array.Empty<LinterOutput>();
            }

            var resourceTypes = expression.PolicyRule.If.ReferencedResourceTypes;
            if (resourceTypes.IsEmpty)
            {
                return Array.Empty<LinterOutput>();
            }

            foreach (var resourceType in resourceTypes)
            {
                if (!context.ResourceTypeMetadata.TryGetResourceTypeCapabilities(resourceType: resourceType, result: out var capabilities) ||
                    !capabilities.HasFlag(flag: ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation) ||
                    resourceType.EqualsOrdinalInsensitively("Microsoft.Resources/resourceGroups") ||
                    resourceType.EqualsOrdinalInsensitively("Microsoft.Resources/subscriptions/resourceGroups") ||
                    resourceType.EqualsOrdinalInsensitively("Microsoft.Resources/subscriptions"))
                {
                    return Array.Empty<LinterOutput>();
                }
            }

            return new[] { this.CreateWarning(expression: mode) };
        }
    }
}
