// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
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
            "The policy uses 'Indexed' mode, which skips evaluation of the referenced resource types: {0}. Set the mode to 'All' to evaluate these types.";

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

            var skippedResourceTypes = new List<string>();
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
                    skippedResourceTypes.Add(item: resourceType);
                }
            }

            if (skippedResourceTypes.Count == 0)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateError(expression: mode != null ? mode : expression, string.Join(", ", skippedResourceTypes
                    .OrderBy(keySelector: resourceType => resourceType, comparer: StringComparer.OrdinalIgnoreCase)
                    .ToArray())),
            };
        }
    }
}
