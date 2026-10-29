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
    /// Tests for the <see cref="AppServiceConfigFieldAlias"/> rule.
    /// </summary>
    public class AppServiceConfigFieldAliasTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        private static string Policy(string condition) => @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": " + condition + @",
      ""then"": { ""effect"": ""deny"" }
    }
  }
}";

        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new AppServiceConfigFieldAlias() },
                metadata: AppServiceConfigFieldAliasTests.TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        private static LinterOutput Output(string alias, int linePosition, string path) => new LinterOutput(
            RuleIdentifier: "app-service-config-field-alias",
            Title: "App Service Config Field Alias",
            Severity: Severity.Warning,
            Category: Category.ResourceFields,
            LineNumber: 4,
            LinePosition: linePosition,
            Path: path,
            Description: $"The field alias '{alias}' checks an App Service setting. These settings can be changed through both the app and its 'config' resource, and some 'siteConfig' properties are returned as null when reading an existing app. Enforce on both resource types and add an 'exists' condition on 'siteConfig' aliases.");

        [Theory]
        [InlineData("Microsoft.Web/sites/siteConfig.ftpsState")]
        [InlineData("Microsoft.Web/sites/slots/siteConfig.ftpsState")]
        [InlineData("Microsoft.Web/sites/config/ftpsState")]
        [InlineData("microsoft.web/sites/slots/config/ftpsState")]
        public void RuleTests_AppServiceConfigFieldAlias_FieldCondition(string alias)
        {
            var results = AppServiceConfigFieldAliasTests.Lint(AppServiceConfigFieldAliasTests.Policy(
                condition: @"{ ""field"": """ + alias + @""", ""notEquals"": ""Disabled"" }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceConfigFieldAliasTests.Output(
                alias: alias,
                linePosition: 25 + alias.Length,
                path: "properties.policyRule.if.field"));
        }

        [Fact]
        public void RuleTests_AppServiceConfigFieldAlias_ValueExpression()
        {
            var results = AppServiceConfigFieldAliasTests.Lint(AppServiceConfigFieldAliasTests.Policy(
                condition: @"{ ""value"": ""[field('Microsoft.Web/sites/siteConfig.minTlsVersion')]"", ""equals"": ""1.0"" }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceConfigFieldAliasTests.Output(
                alias: "Microsoft.Web/sites/siteConfig.minTlsVersion",
                linePosition: 80,
                path: "properties.policyRule.if.value"));
        }

        [Fact]
        public void RuleTests_AppServiceConfigFieldAlias_MultipleReferences()
        {
            var condition = @"{ ""anyOf"": [ { ""field"": ""Microsoft.Web/sites/siteConfig.ftpsState"", ""exists"": true }, { ""field"": ""Microsoft.Web/sites/config/ftpsState"", ""notEquals"": ""Disabled"" } ] }";

            var results = AppServiceConfigFieldAliasTests.Lint(AppServiceConfigFieldAliasTests.Policy(condition: condition));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceConfigFieldAliasTests.Output(
                alias: "Microsoft.Web/sites/siteConfig.ftpsState",
                linePosition: 78,
                path: "properties.policyRule.if.anyOf[0].field"));
        }

        [Theory]
        [InlineData("Microsoft.Web/sites/httpsOnly")]
        [InlineData("Microsoft.Web/sites/config/siteAuthEnabled")]
        [InlineData("Microsoft.Web/sites/slots/config/httpLogs.fileSystem.enabled")]
        [InlineData("type")]
        public void RuleTests_AppServiceConfigFieldAlias_OtherField(string field)
        {
            var results = AppServiceConfigFieldAliasTests.Lint(AppServiceConfigFieldAliasTests.Policy(
                condition: @"{ ""field"": """ + field + @""", ""equals"": ""Microsoft.Web/sites/config"" }"));

            results.Should().BeEmpty();
        }
    }
}
