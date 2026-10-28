// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Flags references to App Service 'siteConfig' field aliases, some of which are returned as null when reading an existing app.
    /// </summary>
    public sealed class AppServiceSiteConfigFieldAlias : LinterRule<Reference>
    {
        private const string RuleTitle = "App Service Site Config Field Alias";

        private const string RuleDescription =
            "The field alias '{0}' maps to a property under 'siteConfig'. Some 'siteConfig' properties are returned as null when reading an existing app, even when they are set, which can cause unexpected enforcement and incorrect compliance results. For compliance, check the matching alias on the app's 'config' resource.";

        private static readonly string[] SiteConfigPrefixes = new[]
        {
            "Microsoft.Web/sites/siteConfig.",
            "Microsoft.Web/sites/slots/siteConfig.",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="AppServiceSiteConfigFieldAlias"/> class.
        /// </summary>
        public AppServiceSiteConfigFieldAlias() : base(
            identifier: "app-service-site-config-field-alias",
            category: Category.ResourceFields,
            title: AppServiceSiteConfigFieldAlias.RuleTitle,
            descriptionFormat: AppServiceSiteConfigFieldAlias.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Reference expression, LinterContext context)
        {
            if (expression.IsResolvedFieldReference() &&
                Array.Exists(AppServiceSiteConfigFieldAlias.SiteConfigPrefixes, prefix => expression.Identifier.StartsWithOrdinalInsensitively(prefix)))
            {
                return new[]
                {
                    this.CreateWarning(expression, expression.Identifier),
                };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
