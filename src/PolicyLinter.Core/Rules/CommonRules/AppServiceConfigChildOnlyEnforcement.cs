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

    /// <summary>
    /// Flags enforcement policies on the App Service config resource type that don't also target the app itself.
    /// </summary>
    public sealed class AppServiceConfigChildOnlyEnforcement : LinterRule<PolicyRule>
    {
        private const string RuleTitle = "App Service Config Child-Only Enforcement";

        private const string RuleDescription =
            "The policy enforces on the '{0}' resource type but not on '{1}'. App settings set through the 'siteConfig' property of the app are not evaluated by this policy. Also enforce on '{1}'.";

        /// <summary>
        /// The config resource types and the app resource types that can set the same settings.
        /// </summary>
        private static readonly (string Config, string App)[] ResourceTypes = new[]
        {
            ("Microsoft.Web/sites/config", "Microsoft.Web/sites"),
            ("Microsoft.Web/sites/slots/config", "Microsoft.Web/sites/slots"),
        };

        private static readonly OrdinalInsensitiveHashSet EnforcementEffects = new OrdinalInsensitiveHashSet
        {
            "append",
            "deny",
            "modify",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="AppServiceConfigChildOnlyEnforcement"/> class.
        /// </summary>
        public AppServiceConfigChildOnlyEnforcement() : base(
            identifier: "app-service-config-child-only-enforcement",
            category: Category.BestPractices,
            title: AppServiceConfigChildOnlyEnforcement.RuleTitle,
            descriptionFormat: AppServiceConfigChildOnlyEnforcement.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyRule expression, LinterContext context)
        {
            if (!AppServiceConfigChildOnlyEnforcement.CanEnforce(effect: expression.Then.Effect, context: context))
            {
                return Array.Empty<LinterOutput>();
            }

            var resourceTypes = expression.If.ReferencedResourceTypes;

            return AppServiceConfigChildOnlyEnforcement.ResourceTypes
                .Where(pair => resourceTypes.Contains(pair.Config) && !resourceTypes.Contains(pair.App))
                .Select(pair => this.CreateWarning(expression.If, pair.Config, pair.App))
                .ToArray();
        }

        /// <summary>
        /// Determines whether the effect is an enforcement effect, or a parameter whose allowedValues include one.
        /// </summary>
        private static bool CanEnforce(Property effect, LinterContext context)
        {
            if (effect.HasLiteralValue)
            {
                return AppServiceConfigChildOnlyEnforcement.EnforcementEffects.Contains(effect.Value.ToString());
            }

            return effect.HasSimpleParameterizedValue(context: context, out _, out var allowedValues, out _) &&
                allowedValues != null &&
                allowedValues.Any(value => AppServiceConfigChildOnlyEnforcement.EnforcementEffects.Contains(value));
        }
    }
}
