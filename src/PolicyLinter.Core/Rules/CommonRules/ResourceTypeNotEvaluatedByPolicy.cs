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
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Flags policies that target resource types that Azure Policy doesn't evaluate.
    /// </summary>
    public sealed class ResourceTypeNotEvaluatedByPolicy : LinterRule<IfCondition>
    {
        private const string RuleTitle = "Resource Type Not Evaluated by Policy";

        private const string RuleDescription =
            "The policy targets the resource type '{0}', which Azure Policy doesn't evaluate. The policy has no effect on resources of this type.";

        /// <summary>
        /// Resource type prefixes that Azure Policy doesn't evaluate.
        /// </summary>
        private static readonly string[] NotEvaluatedPrefixes = new[]
        {
            "Microsoft.Resources/",
            "Microsoft.Billing/",
            "Microsoft.Capacity/reservationOrders/",
            "Microsoft.Help/",
            "Microsoft.Diagnostics/",
        };

        /// <summary>
        /// Resource types that Azure Policy doesn't evaluate.
        /// </summary>
        private static readonly OrdinalInsensitiveHashSet NotEvaluatedResourceTypes = new OrdinalInsensitiveHashSet
        {
            "Microsoft.ServiceBus/namespaces/topics",
            "Microsoft.ServiceBus/namespaces/topics/authorizationRules",
            "Microsoft.ServiceBus/namespaces/topics/subscriptions",
            "Microsoft.ServiceBus/namespaces/topics/subscriptions/rules",
        };

        /// <summary>
        /// Resource types under the prefixes above that Azure Policy evaluates.
        /// </summary>
        private static readonly OrdinalInsensitiveHashSet EvaluatedResourceTypes = new OrdinalInsensitiveHashSet
        {
            "Microsoft.Resources/subscriptions",
            "Microsoft.Resources/subscriptions/resourceGroups",
            "Microsoft.Resources/resourceGroups",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceTypeNotEvaluatedByPolicy"/> class.
        /// </summary>
        public ResourceTypeNotEvaluatedByPolicy() : base(
            identifier: "resource-type-not-evaluated-by-policy",
            category: Category.ResourceFields,
            title: ResourceTypeNotEvaluatedByPolicy.RuleTitle,
            descriptionFormat: ResourceTypeNotEvaluatedByPolicy.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(IfCondition expression, LinterContext context)
        {
            if (!context.IsControlPlanePolicyMode)
            {
                return Array.Empty<LinterOutput>();
            }

            return expression.ReferencedResourceTypes
                .Where(ResourceTypeNotEvaluatedByPolicy.IsNotEvaluated)
                .Select(resourceType => this.CreateError(expression, resourceType))
                .ToArray();
        }

        /// <summary>
        /// Determines whether Azure Policy doesn't evaluate the resource type.
        /// </summary>
        private static bool IsNotEvaluated(string resourceType)
        {
            return ResourceTypeNotEvaluatedByPolicy.NotEvaluatedResourceTypes.Contains(resourceType) ||
                (!ResourceTypeNotEvaluatedByPolicy.EvaluatedResourceTypes.Contains(resourceType) &&
                    ResourceTypeNotEvaluatedByPolicy.NotEvaluatedPrefixes.Any(prefix => resourceType.StartsWithOrdinalInsensitively(prefix)));
        }
    }
}
