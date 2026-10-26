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
    /// Tests for the <see cref="NsgSecurityRuleChildOnlyEnforcement"/> rule.
    /// </summary>
    public class NsgSecurityRuleChildOnlyEnforcementTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        private const string ChildOnlyCondition = @"{
        ""allOf"": [
          { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups/securityRules"" },
          { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules/access"", ""equals"": ""Allow"" }
        ]
      }";

        private static readonly LinterOutput ExpectedOutput = new LinterOutput(
            RuleIdentifier: "nsg-security-rule-child-only-enforcement",
            Title: "NSG Security Rule Child-Only Enforcement",
            Severity: Severity.Warning,
            Category: Category.BestPractices,
            LineNumber: 4,
            LinePosition: 13,
            Path: "properties.policyRule.if",
            Description: "The policy enforces on the 'Microsoft.Network/networkSecurityGroups/securityRules' resource type but not on 'Microsoft.Network/networkSecurityGroups'. Security rules created or changed through the parent network security group are not evaluated by this policy. Also enforce on the parent network security group.");

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
                rules: new ILinterRule[] { new NsgSecurityRuleChildOnlyEnforcement() },
                metadata: NsgSecurityRuleChildOnlyEnforcementTests.TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        [Theory]
        [InlineData("deny")]
        [InlineData("Modify")]
        [InlineData("append")]
        public void RuleTests_NsgSecurityRuleChildOnlyEnforcement_EnforcementEffect(string effect)
        {
            var results = NsgSecurityRuleChildOnlyEnforcementTests.Lint(NsgSecurityRuleChildOnlyEnforcementTests.Policy(
                condition: NsgSecurityRuleChildOnlyEnforcementTests.ChildOnlyCondition,
                effect: effect));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(NsgSecurityRuleChildOnlyEnforcementTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleChildOnlyEnforcement_ParameterAllowsEnforcementEffect()
        {
            var results = NsgSecurityRuleChildOnlyEnforcementTests.Lint(NsgSecurityRuleChildOnlyEnforcementTests.Policy(
                condition: NsgSecurityRuleChildOnlyEnforcementTests.ChildOnlyCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [ ""Audit"", ""Deny"", ""Disabled"" ], ""defaultValue"": ""Audit"" } }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(NsgSecurityRuleChildOnlyEnforcementTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleChildOnlyEnforcement_ParameterAllowsOnlyAuditEffects()
        {
            var results = NsgSecurityRuleChildOnlyEnforcementTests.Lint(NsgSecurityRuleChildOnlyEnforcementTests.Policy(
                condition: NsgSecurityRuleChildOnlyEnforcementTests.ChildOnlyCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [ ""Audit"", ""Disabled"" ] } }"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleChildOnlyEnforcement_ParameterWithoutAllowedValues()
        {
            var results = NsgSecurityRuleChildOnlyEnforcementTests.Lint(NsgSecurityRuleChildOnlyEnforcementTests.Policy(
                condition: NsgSecurityRuleChildOnlyEnforcementTests.ChildOnlyCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""defaultValue"": ""Deny"" } }"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleChildOnlyEnforcement_AuditEffect()
        {
            var results = NsgSecurityRuleChildOnlyEnforcementTests.Lint(NsgSecurityRuleChildOnlyEnforcementTests.Policy(
                condition: NsgSecurityRuleChildOnlyEnforcementTests.ChildOnlyCondition,
                effect: "audit"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleChildOnlyEnforcement_BothResourceTypes()
        {
            var condition = @"{
        ""anyOf"": [
          " + NsgSecurityRuleChildOnlyEnforcementTests.ChildOnlyCondition + @",
          {
            ""allOf"": [
              { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" },
              {
                ""count"": {
                  ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*]"",
                  ""where"": { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Allow"" }
                },
                ""greater"": 0
              }
            ]
          }
        ]
      }";

            var results = NsgSecurityRuleChildOnlyEnforcementTests.Lint(NsgSecurityRuleChildOnlyEnforcementTests.Policy(condition: condition));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleChildOnlyEnforcement_BothResourceTypesInTypeCondition()
        {
            var condition = @"{
        ""field"": ""type"",
        ""in"": [ ""Microsoft.Network/networkSecurityGroups/securityRules"", ""microsoft.network/networkSecurityGroups"" ]
      }";

            var results = NsgSecurityRuleChildOnlyEnforcementTests.Lint(NsgSecurityRuleChildOnlyEnforcementTests.Policy(condition: condition));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleChildOnlyEnforcement_OtherResourceType()
        {
            var condition = @"{ ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" }";

            var results = NsgSecurityRuleChildOnlyEnforcementTests.Lint(NsgSecurityRuleChildOnlyEnforcementTests.Policy(condition: condition));

            results.Should().BeEmpty();
        }
    }
}
