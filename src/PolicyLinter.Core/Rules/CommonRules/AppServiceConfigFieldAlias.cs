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
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Flags policy conditions that check App Service settings through 'siteConfig' or 'config' field aliases. These settings
    /// can be changed through both the app and its config resource, and some 'siteConfig' properties are returned as null.
    /// </summary>
    public sealed class AppServiceConfigFieldAlias : LinterRule<IfCondition>
    {
        private const string RuleTitle = "App Service Config Field Alias";

        private const string RuleDescription =
            "The field alias '{0}' checks an App Service setting. These settings can be changed through both the app and its 'config' resource, and some 'siteConfig' properties are returned as null when reading an existing app. Enforce on both resource types and add an 'exists' condition on 'siteConfig' aliases.";

        /// <summary>
        /// The 'siteConfig' field alias prefixes and the matching 'config' field alias prefixes.
        /// </summary>
        private static readonly (string SiteConfig, string Config)[] AliasPrefixes = new[]
        {
            ("Microsoft.Web/sites/siteConfig.", "Microsoft.Web/sites/config/"),
            ("Microsoft.Web/sites/slots/siteConfig.", "Microsoft.Web/sites/slots/config/"),
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="AppServiceConfigFieldAlias"/> class.
        /// </summary>
        public AppServiceConfigFieldAlias() : base(
            identifier: "app-service-config-field-alias",
            category: Category.ResourceFields,
            title: AppServiceConfigFieldAlias.RuleTitle,
            descriptionFormat: AppServiceConfigFieldAlias.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(IfCondition expression, LinterContext context)
        {
            Reference? firstReference = null;
            expression.Visit(new PolicyExpressionVisitor
            {
                Visit = node =>
                {
                    if (firstReference == null &&
                        node is Reference reference &&
                        reference.IsResolvedFieldReference() &&
                        AppServiceConfigFieldAlias.IsSiteConfigSetting(alias: reference.Identifier, metadata: context.ResourceTypeMetadata))
                    {
                        firstReference = reference;
                    }
                },
            });

            if (firstReference != null)
            {
                return new[]
                {
                    this.CreateWarning(firstReference, firstReference.Identifier),
                };
            }

            return Array.Empty<LinterOutput>();
        }

        /// <summary>
        /// Determines whether the alias is a 'siteConfig' alias, or a 'config' alias whose setting also has a 'siteConfig' alias.
        /// Other config resources, such as authentication and logging settings, can't be set through 'siteConfig'.
        /// </summary>
        private static bool IsSiteConfigSetting(string alias, ITypeMetadata metadata)
        {
            return AppServiceConfigFieldAlias.AliasPrefixes.Any(prefixes =>
                alias.StartsWithOrdinalInsensitively(prefixes.SiteConfig) ||
                (alias.StartsWithOrdinalInsensitively(prefixes.Config) &&
                    metadata.TryGetAliasPropertyMetadata(prefixes.SiteConfig + alias.Substring(prefixes.Config.Length), out var siteConfigMetadata) &&
                    siteConfigMetadata.Length > 0));
        }
    }
}