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
    /// Tests for the <see cref="AppServiceConfigChildOnlyEnforcement"/> rule.
    /// </summary>
    public class AppServiceConfigChildOnlyEnforcementTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        private const string ConfigCondition = @"{
        ""allOf"": [
          { ""field"": ""type"", ""equals"": ""Microsoft.Web/sites/config"" },
          { ""field"": ""Microsoft.Web/sites/config/ftpsState"", ""equals"": ""AllAllowed"" }
        ]
      }";

        private const string SiteCondition = @"{
        ""allOf"": [
          { ""field"": ""type"", ""equals"": ""Microsoft.Web/sites"" },
          { ""field"": ""Microsoft.Web/sites/siteConfig.ftpsState"", ""exists"": true },
          { ""field"": ""Microsoft.Web/sites/siteConfig.ftpsState"", ""equals"": ""AllAllowed"" }
        ]
      }";

        private static readonly LinterOutput ExpectedOutput = AppServiceConfigChildOnlyEnforcementTests.Output("Microsoft.Web/sites/config", "Microsoft.Web/sites");

        private static LinterOutput Output(string config, string app) => new LinterOutput(
            RuleIdentifier: "app-service-config-child-only-enforcement",
            Title: "App Service Config Child-Only Enforcement",
            Severity: Severity.Warning,
            Category: Category.BestPractices,
            LineNumber: 4,
            LinePosition: 13,
            Path: "properties.policyRule.if",
            Description: $"The policy enforces on the '{config}' resource type but not on '{app}'. App settings set through the 'siteConfig' property of the app are not evaluated by this policy. Also enforce on '{app}'.");

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
                rules: new ILinterRule[] { new AppServiceConfigChildOnlyEnforcement() },
                metadata: AppServiceConfigChildOnlyEnforcementTests.TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        [Theory]
        [InlineData("deny")]
        [InlineData("Modify")]
        [InlineData("append")]
        public void RuleTests_AppServiceConfigChildOnlyEnforcement_EnforcementEffect(string effect)
        {
            var results = AppServiceConfigChildOnlyEnforcementTests.Lint(AppServiceConfigChildOnlyEnforcementTests.Policy(
                condition: AppServiceConfigChildOnlyEnforcementTests.ConfigCondition,
                effect: effect));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceConfigChildOnlyEnforcementTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_AppServiceConfigChildOnlyEnforcement_SlotConfig()
        {
            var condition = @"{ ""field"": ""Microsoft.Web/sites/slots/config/ftpsState"", ""equals"": ""AllAllowed"" }";

            var results = AppServiceConfigChildOnlyEnforcementTests.Lint(AppServiceConfigChildOnlyEnforcementTests.Policy(condition: condition));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceConfigChildOnlyEnforcementTests.Output("Microsoft.Web/sites/slots/config", "Microsoft.Web/sites/slots"));
        }

        [Fact]
        public void RuleTests_AppServiceConfigChildOnlyEnforcement_ParameterAllowsEnforcementEffect()
        {
            var results = AppServiceConfigChildOnlyEnforcementTests.Lint(AppServiceConfigChildOnlyEnforcementTests.Policy(
                condition: AppServiceConfigChildOnlyEnforcementTests.ConfigCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [ ""Audit"", ""Deny"", ""Disabled"" ], ""defaultValue"": ""Audit"" } }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(AppServiceConfigChildOnlyEnforcementTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_AppServiceConfigChildOnlyEnforcement_ParameterAllowsOnlyAuditEffects()
        {
            var results = AppServiceConfigChildOnlyEnforcementTests.Lint(AppServiceConfigChildOnlyEnforcementTests.Policy(
                condition: AppServiceConfigChildOnlyEnforcementTests.ConfigCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [ ""Audit"", ""Disabled"" ] } }"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_AppServiceConfigChildOnlyEnforcement_ParameterWithoutAllowedValues()
        {
            var results = AppServiceConfigChildOnlyEnforcementTests.Lint(AppServiceConfigChildOnlyEnforcementTests.Policy(
                condition: AppServiceConfigChildOnlyEnforcementTests.ConfigCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""defaultValue"": ""Deny"" } }"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_AppServiceConfigChildOnlyEnforcement_AuditEffect()
        {
            var results = AppServiceConfigChildOnlyEnforcementTests.Lint(AppServiceConfigChildOnlyEnforcementTests.Policy(
                condition: AppServiceConfigChildOnlyEnforcementTests.ConfigCondition,
                effect: "audit"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_AppServiceConfigChildOnlyEnforcement_BothResourceTypes()
        {
            var condition = @"{ ""anyOf"": [ " + AppServiceConfigChildOnlyEnforcementTests.ConfigCondition + ", " + AppServiceConfigChildOnlyEnforcementTests.SiteCondition + " ] }";

            var results = AppServiceConfigChildOnlyEnforcementTests.Lint(AppServiceConfigChildOnlyEnforcementTests.Policy(condition: condition));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_AppServiceConfigChildOnlyEnforcement_AppOnly()
        {
            var results = AppServiceConfigChildOnlyEnforcementTests.Lint(AppServiceConfigChildOnlyEnforcementTests.Policy(
                condition: AppServiceConfigChildOnlyEnforcementTests.SiteCondition));

            results.Should().BeEmpty();
        }
    }
}
