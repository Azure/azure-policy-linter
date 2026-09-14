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
    /// Detects Indexed-mode policies referencing resource types that require All mode.
    /// </summary>
    public sealed class IndexedModeWithNonIndexableResourceTypes : LinterRule<PolicyDefinitionProperties>
    {
        private const string RuleTitle = "Indexed Mode With Non-Indexable Resource Types";
        private const string RuleDescription =
            "The policy mode 'Indexed' does not evaluate the referenced resource type '{0}'. Set the mode to 'All' to include this resource type in policy evaluation.";

        /// <summary>
        /// Initializes a new instance of the <see cref="IndexedModeWithNonIndexableResourceTypes"/> class.
        /// </summary>
        public IndexedModeWithNonIndexableResourceTypes() : base(
            identifier: "indexed-mode-with-non-indexable-resource-types",
            category: Category.ResourceFields,
            title: IndexedModeWithNonIndexableResourceTypes.RuleTitle,
            descriptionFormat: IndexedModeWithNonIndexableResourceTypes.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyDefinitionProperties expression, LinterContext context)
        {
            var mode = expression.Mode;
            if (mode != null && !mode.HasLiteralValue)
            {
                return Array.Empty<LinterOutput>();
            }

            var modeName = mode?.Value.ToString();
            if (!string.IsNullOrWhiteSpace(value: modeName) && !modeName.EqualsOrdinalInsensitively("Indexed"))
            {
                return Array.Empty<LinterOutput>();
            }

            foreach (var resourceType in expression.PolicyRule.If.ReferencedResourceTypes)
            {
                if (!context.ResourceTypeMetadata.TryGetResourceTypeCapabilities(resourceType: resourceType, result: out var capabilities))
                {
                    continue;
                }

                if (!capabilities.HasFlag(flag: ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation) ||
                    resourceType.EqualsOrdinalInsensitively("Microsoft.Resources/resourceGroups") ||
                    resourceType.EqualsOrdinalInsensitively("Microsoft.Resources/subscriptions/resourceGroups") ||
                    resourceType.EqualsOrdinalInsensitively("Microsoft.Resources/subscriptions"))
                {
                    return new[] { this.CreateError(expression: mode != null ? mode : expression, resourceType) };
                }
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
