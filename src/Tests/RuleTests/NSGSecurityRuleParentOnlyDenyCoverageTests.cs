// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="NSGSecurityRuleParentOnlyDenyCoverage"/> rule.
    /// </summary>
    public class NSGSecurityRuleParentOnlyDenyCoverageTests
    {
        private const string ParentAlias = "Microsoft.Network/networkSecurityGroups/securityRules[*].access";
        private const string ChildAlias = "Microsoft.Network/networkSecurityGroups/securityRules/access";

        /// <summary>
        /// The real type metadata, required because the rule inspects resolved field aliases.
        /// </summary>
        private static readonly TypeMetadata TypeMetadata = new TypeMetadata(
            metadataProvider: new OfflineMetadataProvider(),
            aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_ParentMemberAlias()
        {
            var ifCondition = $@"{{ ""field"": ""{ParentAlias}"", ""equals"": ""Allow"" }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(ifCondition: ifCondition);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(NSGSecurityRuleParentOnlyDenyCoverageTests.ExpectedOutput(
                lineNumber: 7,
                linePosition: 104,
                path: "properties.policyRule.if.field",
                alias: NSGSecurityRuleParentOnlyDenyCoverageTests.ParentAlias));
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_ParentCollectionAlias()
        {
            var ifCondition = @"{ ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules"", ""exists"": ""true"" }";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(ifCondition: ifCondition);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(NSGSecurityRuleParentOnlyDenyCoverageTests.ExpectedOutput(
                lineNumber: 7,
                linePosition: 94,
                path: "properties.policyRule.if.field",
                alias: "Microsoft.Network/networkSecurityGroups/securityRules"));
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_CountField()
        {
            var ifCondition = @"{
                ""count"": {
                    ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*]""
                },
                ""greater"": 0
            }";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(ifCondition: ifCondition);

            results.Should().HaveCount(1);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_FieldFunction()
        {
            var ifCondition = $@"{{ ""value"": ""[field('{ParentAlias}')]"", ""equals"": ""Allow"" }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(ifCondition: ifCondition);

            results.Should().HaveCount(1);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_AliasCasingIsIgnored()
        {
            var ifCondition = @"{ ""field"": ""MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES[*].ACCESS"", ""equals"": ""Allow"" }";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(ifCondition: ifCondition);

            results.Should().HaveCount(1);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_EffectParameterAllowsDeny()
        {
            var ifCondition = $@"{{ ""field"": ""{ParentAlias}"", ""equals"": ""Allow"" }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                effect: @"[parameters('effect')]",
                allowedValues: @"[""audit"", ""deny""]");

            results.Should().HaveCount(1);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_UnconstrainedEffectParameter()
        {
            var ifCondition = $@"{{ ""field"": ""{ParentAlias}"", ""equals"": ""Allow"" }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                effect: @"[parameters('effect')]",
                allowedValues: null);

            results.Should().HaveCount(1);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_RepeatedParentAliasesFireOnce()
        {
            var ifCondition = $@"{{
                ""allOf"": [
                    {{ ""field"": ""{ParentAlias}"", ""equals"": ""Allow"" }},
                    {{ ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].direction"", ""equals"": ""Inbound"" }}
                ]
            }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(ifCondition: ifCondition);

            results.Should().HaveCount(1);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_ChildAliasAlsoReferenced_NoFinding()
        {
            var ifCondition = $@"{{
                ""anyOf"": [
                    {{ ""field"": ""{ParentAlias}"", ""equals"": ""Allow"" }},
                    {{ ""field"": ""{ChildAlias}"", ""equals"": ""Allow"" }}
                ]
            }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(ifCondition: ifCondition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_NoSecurityRuleAlias_NoFinding()
        {
            var ifCondition = @"{ ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" }";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(ifCondition: ifCondition);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData(@"""audit""")]
        [InlineData(@"""modify""")]
        [InlineData(@"""disabled""")]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_NonDenyEffect_NoFinding(string effect)
        {
            var ifCondition = $@"{{ ""field"": ""{ParentAlias}"", ""equals"": ""Allow"" }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                effect: effect.Trim('"'));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_EffectParameterExcludesDeny_NoFinding()
        {
            var ifCondition = $@"{{ ""field"": ""{ParentAlias}"", ""equals"": ""Allow"" }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                effect: @"[parameters('effect')]",
                allowedValues: @"[""audit"", ""disabled""]");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_ComplexEffectExpression_NoFinding()
        {
            var ifCondition = $@"{{ ""field"": ""{ParentAlias}"", ""equals"": ""Allow"" }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                effect: "[concat('de', 'ny')]");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_UnrelatedArrayAlias_NoFinding()
        {
            var ifCondition = @"{ ""field"": ""Microsoft.Network/networkSecurityGroups/defaultSecurityRules[*].access"", ""equals"": ""Allow"" }";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(ifCondition: ifCondition);

            results.Should().BeEmpty();
        }

        private static LinterOutput[] Lint(
            string ifCondition,
            string effect = "deny",
            string allowedValues = null!,
            string mode = "All")
        {
            var parameters = effect.StartsWith("[parameters(", StringComparison.Ordinal)
                ? @"""parameters"": { ""effect"": { ""type"": ""String""" +
                    (allowedValues == null ? string.Empty : @", ""allowedValues"": " + allowedValues) +
                    @" } },"
                : string.Empty;

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""mode"": ""{mode}"",
                    {parameters}
                    ""policyRule"": {{
                      ""if"": {ifCondition},
                      ""then"": {{ ""effect"": ""{effect}"" }}
                    }}
                  }}
                }}";

            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new NSGSecurityRuleParentOnlyDenyCoverage() },
                metadata: NSGSecurityRuleParentOnlyDenyCoverageTests.TypeMetadata);

            return linter.Lint(rawPolicyDefinition: policyDefinition);
        }

        private static LinterOutput ExpectedOutput(
            int lineNumber,
            int linePosition,
            string path,
            string alias)
        {
            return new LinterOutput(
                RuleIdentifier: "nsg-security-rule-parent-only-deny-coverage",
                Title: "NSG Security Rule Parent-Only Deny Coverage",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: lineNumber,
                LinePosition: linePosition,
                Path: path,
                Description: $"The alias '{alias}' applies to security rules submitted with the parent network security group. Requests that directly create or update 'securityRules' child resources are not covered. Add equivalent child resource coverage in this or another policy.");
        }
    }
}
