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
    /// Tests for the <see cref="AppServiceConfigParentOnlyEnforcement"/> rule.
    /// </summary>
    public class AppServiceConfigParentOnlyEnforcementTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        private const string SiteCondition = @"{
        ""allOf"": [
          { ""field"": ""type"", ""equals"": ""Microsoft.Web/sites"" },
          { ""field"": ""Microsoft.Web/sites/siteConfig.ftpsState"", ""exists"": true },
          { ""field"": ""Microsoft.Web/sites/siteConfig.ftpsState"", ""equals"": ""AllAllowed"" }
        ]
      }";

        private const string ConfigCondition = @"{
        ""allOf"": [
          { ""field"": ""type"", ""equals"": ""Microsoft.Web/sites/config"" },
          { ""field"": ""Microsoft.Web/sites/config/ftpsState"", ""equals"": ""AllAllowed"" }
        ]
      }";

        private static readonly LinterOutput ExpectedOutput = AppServiceConfigParentOnlyEnforcementTests.Output("Microsoft.Web/sites/siteConfig.", "Microsoft.Web/sites/config");

        private static LinterOutput Output(string prefix, string config) => new LinterOutput(
            RuleIdentifier: "app-service-config-parent-only-enforcement",
            Title: "App Service Config Parent-Only Enforcement",
            Severity: Severity.Warning,
            Category: Category.BestPractices,
            LineNumber: 4,
            LinePosition: 13,
            Path: "properties.policyRule.if",
            Description: $"The policy enforces on app settings through '{prefix}*' field aliases but not on the '{config}' resource type. App settings changed through the app's '{config}' resource are not evaluated by this policy. Also enforce on '{config}'.");

        /// <summary>
        /// Builds a policy definition with the given 'if' condition, effect, and parameters.
        /// </summary>
        private static string Policy(string condition, string effect = "deny", string parameters = "{}") => @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": " + condition + @",
      ""then"": { ""effect"": """ + effect + @""" }
    },
    ""parameters"": " + parameters + @"
  }
}";

        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new AppServiceConfigParentOnlyEnforcement() },
                metadata: AppServiceConfigParentOnlyEnforcementTests.TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        [Theory]
        [InlineData("deny")]
        [InlineData("Modify")]
        [InlineData("append")]
        public void RuleTests_AppServiceConfigParentOnlyEnforcement_EnforcementEffect(string effect)
        {
            var results = AppServiceConfigParentOnlyEnforcementTests.Lint(AppServiceConfigParentOnlyEnforcementTests.Policy(
                condition: AppServiceConfigParentOnlyEnforcementTests.SiteCondition,
                effect: effect));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceConfigParentOnlyEnforcementTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_AppServiceConfigParentOnlyEnforcement_SlotSiteConfig()
        {
            var condition = @"{ ""field"": ""Microsoft.Web/sites/slots/siteConfig.ftpsState"", ""equals"": ""AllAllowed"" }";

            var results = AppServiceConfigParentOnlyEnforcementTests.Lint(AppServiceConfigParentOnlyEnforcementTests.Policy(condition: condition));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceConfigParentOnlyEnforcementTests.Output("Microsoft.Web/sites/slots/siteConfig.", "Microsoft.Web/sites/slots/config"));
        }

        [Fact]
        public void RuleTests_AppServiceConfigParentOnlyEnforcement_ParameterAllowsEnforcementEffect()
        {
            var results = AppServiceConfigParentOnlyEnforcementTests.Lint(AppServiceConfigParentOnlyEnforcementTests.Policy(
                condition: AppServiceConfigParentOnlyEnforcementTests.SiteCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [ ""Audit"", ""Deny"", ""Disabled"" ], ""defaultValue"": ""Audit"" } }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceConfigParentOnlyEnforcementTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_AppServiceConfigParentOnlyEnforcement_ParameterWithoutAllowedValues()
        {
            var results = AppServiceConfigParentOnlyEnforcementTests.Lint(AppServiceConfigParentOnlyEnforcementTests.Policy(
                condition: AppServiceConfigParentOnlyEnforcementTests.SiteCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""defaultValue"": ""Deny"" } }"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_AppServiceConfigParentOnlyEnforcement_AuditEffect()
        {
            var results = AppServiceConfigParentOnlyEnforcementTests.Lint(AppServiceConfigParentOnlyEnforcementTests.Policy(
                condition: AppServiceConfigParentOnlyEnforcementTests.SiteCondition,
                effect: "audit"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_AppServiceConfigParentOnlyEnforcement_BothResourceTypes()
        {
            var condition = @"{ ""anyOf"": [ " + AppServiceConfigParentOnlyEnforcementTests.SiteCondition + ", " + AppServiceConfigParentOnlyEnforcementTests.ConfigCondition + " ] }";

            var results = AppServiceConfigParentOnlyEnforcementTests.Lint(AppServiceConfigParentOnlyEnforcementTests.Policy(condition: condition));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_AppServiceConfigParentOnlyEnforcement_AppWithoutSiteConfig()
        {
            var condition = @"{ ""field"": ""Microsoft.Web/sites/httpsOnly"", ""equals"": false }";

            var results = AppServiceConfigParentOnlyEnforcementTests.Lint(AppServiceConfigParentOnlyEnforcementTests.Policy(condition: condition));

            results.Should().BeEmpty();
        }
    }
}
