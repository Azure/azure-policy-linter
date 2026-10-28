namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="AppServiceSiteConfigFieldAlias"/> rule.
    /// </summary>
    public class AppServiceSiteConfigFieldAliasTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        private static string Policy(string condition, string effect = "audit") => @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": " + condition + @",
      ""then"": { ""effect"": """ + effect + @""" }
    }
  }
}";

        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new AppServiceSiteConfigFieldAlias() },
                metadata: AppServiceSiteConfigFieldAliasTests.TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        private static LinterOutput Output(string alias, int linePosition, string path) => new LinterOutput(
            RuleIdentifier: "app-service-site-config-field-alias",
            Title: "App Service Site Config Field Alias",
            Severity: Severity.Warning,
            Category: Category.ResourceFields,
            LineNumber: 4,
            LinePosition: linePosition,
            Path: path,
            Description: $"The field alias '{alias}' maps to a property under 'siteConfig'. Some 'siteConfig' properties are returned as null when reading an existing app, even when they are set, which can cause unexpected enforcement and incorrect compliance results. For compliance, check the matching alias on the app's 'config' resource.");

        [Theory]
        [InlineData("audit")]
        [InlineData("deny")]
        public void RuleTests_AppServiceSiteConfigFieldAlias_FieldCondition(string effect)
        {
            var results = AppServiceSiteConfigFieldAliasTests.Lint(AppServiceSiteConfigFieldAliasTests.Policy(
                condition: @"{ ""field"": ""Microsoft.Web/sites/siteConfig.ftpsState"", ""notEquals"": ""Disabled"" }",
                effect: effect));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceSiteConfigFieldAliasTests.Output(
                alias: "Microsoft.Web/sites/siteConfig.ftpsState",
                linePosition: 65,
                path: "properties.policyRule.if.field"));
        }

        [Fact]
        public void RuleTests_AppServiceSiteConfigFieldAlias_SlotFieldInValueExpression()
        {
            var results = AppServiceSiteConfigFieldAliasTests.Lint(AppServiceSiteConfigFieldAliasTests.Policy(
                condition: @"{ ""value"": ""[field('Microsoft.Web/sites/slots/siteConfig.minTlsVersion')]"", ""equals"": ""1.0"" }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceSiteConfigFieldAliasTests.Output(
                alias: "Microsoft.Web/sites/slots/siteConfig.minTlsVersion",
                linePosition: 86,
                path: "properties.policyRule.if.value"));
        }

        [Fact]
        public void RuleTests_AppServiceSiteConfigFieldAlias_EachReference()
        {
            var results = AppServiceSiteConfigFieldAliasTests.Lint(AppServiceSiteConfigFieldAliasTests.Policy(
                condition: @"{ ""allOf"": [ { ""field"": ""Microsoft.Web/sites/siteConfig.ftpsState"", ""exists"": true }, { ""field"": ""Microsoft.Web/sites/siteConfig.ftpsState"", ""notEquals"": ""Disabled"" } ] }"));

            results.Should().HaveCount(2);
        }

        [Theory]
        [InlineData("Microsoft.Web/sites/config/ftpsState")]
        [InlineData("Microsoft.Web/sites/httpsOnly")]
        public void RuleTests_AppServiceSiteConfigFieldAlias_OtherAlias(string alias)
        {
            var results = AppServiceSiteConfigFieldAliasTests.Lint(AppServiceSiteConfigFieldAliasTests.Policy(
                condition: @"{ ""field"": """ + alias + @""", ""exists"": true }"));

            results.Should().BeEmpty();
        }
    }
}
