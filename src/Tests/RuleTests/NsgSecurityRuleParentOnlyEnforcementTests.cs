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
    /// Tests for the <see cref="NsgSecurityRuleParentOnlyEnforcement"/> rule.
    /// </summary>
    public class NsgSecurityRuleParentOnlyEnforcementTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        private const string ParentOnlyCondition = @"{
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
      }";

        private static readonly LinterOutput ExpectedOutput = new LinterOutput(
            RuleIdentifier: "nsg-security-rule-parent-only-enforcement",
            Title: "NSG Security Rule Parent-Only Enforcement",
            Severity: Severity.Warning,
            Category: Category.BestPractices,
            LineNumber: 4,
            LinePosition: 13,
            Path: "properties.policyRule.if",
            Description: "The policy enforces on security rules through 'Microsoft.Network/networkSecurityGroups/securityRules[*]' fields but not on the 'Microsoft.Network/networkSecurityGroups/securityRules' resource type. Security rules created or changed directly are not evaluated by this policy. Also enforce on the security rule resource type.");

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
                rules: new ILinterRule[] { new NsgSecurityRuleParentOnlyEnforcement() },
                metadata: NsgSecurityRuleParentOnlyEnforcementTests.TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        [Theory]
        [InlineData("deny")]
        [InlineData("Modify")]
        [InlineData("append")]
        public void RuleTests_NsgSecurityRuleParentOnlyEnforcement_EnforcementEffect(string effect)
        {
            var results = NsgSecurityRuleParentOnlyEnforcementTests.Lint(NsgSecurityRuleParentOnlyEnforcementTests.Policy(
                condition: NsgSecurityRuleParentOnlyEnforcementTests.ParentOnlyCondition,
                effect: effect));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(NsgSecurityRuleParentOnlyEnforcementTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleParentOnlyEnforcement_SecurityRulesFieldCondition()
        {
            var condition = @"{
        ""allOf"": [
          { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" },
          { ""field"": ""microsoft.network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Allow"" }
        ]
      }";

            var results = NsgSecurityRuleParentOnlyEnforcementTests.Lint(NsgSecurityRuleParentOnlyEnforcementTests.Policy(condition: condition));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(NsgSecurityRuleParentOnlyEnforcementTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleParentOnlyEnforcement_ParameterAllowsEnforcementEffect()
        {
            var results = NsgSecurityRuleParentOnlyEnforcementTests.Lint(NsgSecurityRuleParentOnlyEnforcementTests.Policy(
                condition: NsgSecurityRuleParentOnlyEnforcementTests.ParentOnlyCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [ ""Audit"", ""Deny"", ""Disabled"" ], ""defaultValue"": ""Audit"" } }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(NsgSecurityRuleParentOnlyEnforcementTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleParentOnlyEnforcement_ParameterWithoutAllowedValues()
        {
            var results = NsgSecurityRuleParentOnlyEnforcementTests.Lint(NsgSecurityRuleParentOnlyEnforcementTests.Policy(
                condition: NsgSecurityRuleParentOnlyEnforcementTests.ParentOnlyCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""defaultValue"": ""Deny"" } }"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleParentOnlyEnforcement_AuditEffect()
        {
            var results = NsgSecurityRuleParentOnlyEnforcementTests.Lint(NsgSecurityRuleParentOnlyEnforcementTests.Policy(
                condition: NsgSecurityRuleParentOnlyEnforcementTests.ParentOnlyCondition,
                effect: "audit"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleParentOnlyEnforcement_NoSecurityRulesField()
        {
            var condition = @"{
        ""allOf"": [
          { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" },
          { ""field"": ""tags['owner']"", ""exists"": false }
        ]
      }";

            var results = NsgSecurityRuleParentOnlyEnforcementTests.Lint(NsgSecurityRuleParentOnlyEnforcementTests.Policy(condition: condition));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NsgSecurityRuleParentOnlyEnforcement_BothResourceTypes()
        {
            var condition = @"{
        ""anyOf"": [
          " + NsgSecurityRuleParentOnlyEnforcementTests.ParentOnlyCondition + @",
          {
            ""allOf"": [
              { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups/securityRules"" },
              { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules/access"", ""equals"": ""Allow"" }
            ]
          }
        ]
      }";

            var results = NsgSecurityRuleParentOnlyEnforcementTests.Lint(NsgSecurityRuleParentOnlyEnforcementTests.Policy(condition: condition));

            results.Should().BeEmpty();
        }
    }
}
