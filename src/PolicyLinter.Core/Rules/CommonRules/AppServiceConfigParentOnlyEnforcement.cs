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
    /// Flags enforcement policies on App Service settings through 'siteConfig' field aliases that don't also target the config resource type.
    /// </summary>
    public sealed class AppServiceConfigParentOnlyEnforcement : LinterRule<PolicyRule>
    {
        private const string RuleTitle = "App Service Config Parent-Only Enforcement";

        private const string RuleDescription =
            "The policy enforces on app settings through '{0}*' field aliases but not on the '{1}' resource type. App settings changed through the app's '{1}' resource are not evaluated by this policy. Also enforce on '{1}'.";

        /// <summary>
        /// The 'siteConfig' field alias prefixes and the config resource types that can change the same settings.
        /// </summary>
        private static readonly (string SiteConfigPrefix, string Config)[] ResourceTypes = new[]
        {
            ("Microsoft.Web/sites/siteConfig.", "Microsoft.Web/sites/config"),
            ("Microsoft.Web/sites/slots/siteConfig.", "Microsoft.Web/sites/slots/config"),
        };

        private static readonly OrdinalInsensitiveHashSet EnforcementEffects = new OrdinalInsensitiveHashSet
        {
            "append",
            "deny",
            "modify",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="AppServiceConfigParentOnlyEnforcement"/> class.
        /// </summary>
        public AppServiceConfigParentOnlyEnforcement() : base(
            identifier: "app-service-config-parent-only-enforcement",
            category: Category.BestPractices,
            title: AppServiceConfigParentOnlyEnforcement.RuleTitle,
            descriptionFormat: AppServiceConfigParentOnlyEnforcement.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyRule expression, LinterContext context)
        {
            if (!AppServiceConfigParentOnlyEnforcement.CanEnforce(effect: expression.Then.Effect, context: context))
            {
                return Array.Empty<LinterOutput>();
            }

            var resourceTypes = expression.If.ReferencedResourceTypes;

            return AppServiceConfigParentOnlyEnforcement.ResourceTypes
                .Where(pair => !resourceTypes.Contains(pair.Config) &&
                    AppServiceConfigParentOnlyEnforcement.ReferencesFieldAliasPrefix(ifCondition: expression.If, prefix: pair.SiteConfigPrefix))
                .Select(pair => this.CreateWarning(expression.If, pair.SiteConfigPrefix, pair.Config))
                .ToArray();
        }

        /// <summary>
        /// Determines whether the effect is an enforcement effect, or a parameter whose allowedValues include one.
        /// </summary>
        private static bool CanEnforce(Property effect, LinterContext context)
        {
            if (effect.HasLiteralValue)
            {
                return AppServiceConfigParentOnlyEnforcement.EnforcementEffects.Contains(effect.Value.ToString());
            }

            return effect.HasSimpleParameterizedValue(context: context, out _, out var allowedValues, out _) &&
                allowedValues != null &&
                allowedValues.Any(value => AppServiceConfigParentOnlyEnforcement.EnforcementEffects.Contains(value));
        }

        /// <summary>
        /// Determines whether the condition references a field alias that starts with the given prefix.
        /// </summary>
        private static bool ReferencesFieldAliasPrefix(IfCondition ifCondition, string prefix)
        {
            var found = false;
            ifCondition.Visit(new PolicyExpressionVisitor
            {
                Visit = node =>
                {
                    if (node is Reference reference &&
                        reference.IsResolvedFieldReference() &&
                        reference.Identifier.StartsWithOrdinalInsensitively(prefix))
                    {
                        found = true;
                    }
                },
            });

            return found;
        }
    }
}
