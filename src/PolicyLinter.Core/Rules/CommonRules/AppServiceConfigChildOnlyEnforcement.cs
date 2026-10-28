// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Flags enforcement policies on App Service settings through the config resource type that don't also target the app itself.
    /// </summary>
    public sealed class AppServiceConfigChildOnlyEnforcement : LinterRule<PolicyRule>
    {
        private const string RuleTitle = "App Service Config Child-Only Enforcement";

        private const string RuleDescription =
            "The policy enforces on the '{0}' resource type but not on '{1}'. App Service settings set through the 'siteConfig' property of the app are not evaluated by this policy. Also enforce on '{1}'.";

        /// <summary>
        /// The config resource types, their field alias prefixes, the app resource types, and the matching 'siteConfig' field alias prefixes.
        /// </summary>
        private static readonly (string Config, string ConfigPrefix, string App, string SiteConfigPrefix)[] ResourceTypes = new[]
        {
            ("Microsoft.Web/sites/config", "Microsoft.Web/sites/config/", "Microsoft.Web/sites", "Microsoft.Web/sites/siteConfig."),
            ("Microsoft.Web/sites/slots/config", "Microsoft.Web/sites/slots/config/", "Microsoft.Web/sites/slots", "Microsoft.Web/sites/slots/siteConfig."),
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
                .Where(types => !resourceTypes.Contains(types.App) &&
                    AppServiceConfigChildOnlyEnforcement.ReferencesConfigAliasWithSiteConfigAlias(
                        ifCondition: expression.If,
                        configPrefix: types.ConfigPrefix,
                        siteConfigPrefix: types.SiteConfigPrefix,
                        metadata: context.ResourceTypeMetadata))
                .Select(types => this.CreateWarning(expression.If, types.Config, types.App))
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

        /// <summary>
        /// Determines whether the condition references a config field alias whose setting can also be set through a 'siteConfig' field alias.
        /// Other config resources, such as 'authsettingsV2' and 'logs', can't be set through 'siteConfig'.
        /// </summary>
        private static bool ReferencesConfigAliasWithSiteConfigAlias(IfCondition ifCondition, string configPrefix, string siteConfigPrefix, ITypeMetadata metadata)
        {
            var found = false;
            ifCondition.Visit(new PolicyExpressionVisitor
            {
                Visit = node =>
                {
                    if (!found &&
                        node is Reference reference &&
                        reference.IsResolvedFieldReference() &&
                        reference.Identifier.StartsWithOrdinalInsensitively(configPrefix) &&
                        metadata.TryGetAliasPropertyMetadata(siteConfigPrefix + reference.Identifier.Substring(configPrefix.Length), out var siteConfigMetadata) &&
                        siteConfigMetadata.Length > 0)
                    {
                        found = true;
                    }
                },
            });

            return found;
        }
    }
}