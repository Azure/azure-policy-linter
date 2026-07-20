namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System.Collections.Generic;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="NSGSecurityRuleChildOnlyDenyCoverage"/> rule.
    /// </summary>
    public class NSGSecurityRuleChildOnlyDenyCoverageTests
    {
        private const string ChildResourceType = "Microsoft.Network/networkSecurityGroups/securityRules";
        private const string ParentResourceType = "Microsoft.Network/networkSecurityGroups";

        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        /// <summary>
        /// Unsupported type conditions that do not select the child resource type.
        /// </summary>
        public static IEnumerable<object[]> UnsupportedTypeConditions => new[]
        {
            new object[] { @"{ ""field"": ""type"", ""like"": ""Microsoft.Network/networkSecurityGroups/*"" }" },
            new object[] { @"{ ""field"": ""type"", ""notEquals"": """ + ChildResourceType + @""" }" },
            new object[] { @"{ ""field"": ""type"", ""notIn"": [""" + ChildResourceType + @"""] }" },
            new object[] { @"{ ""field"": ""type"", ""equals"": ""[parameters('targetType')]"" }" },
            new object[] { @"{ ""field"": ""[concat('ty', 'pe')]"", ""equals"": """ + ChildResourceType + @""" }" },
            new object[] { @"{ ""field"": ""type"", ""equals"": """" }" },
            new object[] { @"{ ""field"": ""type"", ""equals"": ""   "" }" },
            new object[] { @"{ ""field"": ""type"", ""in"": [] }" },
        };

        /// <summary>
        /// Parameterized effects that cannot select deny.
        /// </summary>
        public static IEnumerable<object[]> NonDenyParameterizedEffects => new[]
        {
            new object[]
            {
                @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [""audit"", ""disabled""] } }",
                @"""[parameters('effect')]""",
            },
            new object[]
            {
                @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [] } }",
                @"""[parameters('effect')]""",
            },
            new object[]
            {
                @"{ ""effect"": { ""type"": ""Array"", ""allowedValues"": [[""deny""]] } }",
                @"""[parameters('effect')]""",
            },
            new object[]
            {
                "{}",
                @"""[concat('de', 'ny')]""",
            },
        };

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_LiteralDenyChildEquals()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType));

            NSGSecurityRuleChildOnlyDenyCoverageTests.AssertSingleFinding(results: results);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_CaseInsensitive()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: @"{ ""field"": ""TYPE"", ""equals"": ""MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES"" }",
                effect: @"""DeNy""");

            NSGSecurityRuleChildOnlyDenyCoverageTests.AssertSingleFinding(results: results);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_LiteralDenyChildIn()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: @"{ ""field"": ""type"", ""in"": [""Microsoft.Storage/storageAccounts"", """ + ChildResourceType + @"""] }");

            NSGSecurityRuleChildOnlyDenyCoverageTests.AssertSingleFinding(
                results: results,
                linePosition: 54,
                path: "properties.policyRule.if.in");
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_ChildValueFieldEquals()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: @"{ ""value"": ""[field('type')]"", ""equals"": """ + ChildResourceType + @""" }");

            NSGSecurityRuleChildOnlyDenyCoverageTests.AssertSingleFinding(
                results: results,
                linePosition: 123);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_ChildUnderDoubleNot()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: @"{ ""not"": { ""not"": " +
                    NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType) +
                    @" } }");

            NSGSecurityRuleChildOnlyDenyCoverageTests.AssertSingleFinding(
                results: results,
                linePosition: 130,
                path: "properties.policyRule.if.not.not.equals");
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_ParameterAllowedValuesContainDeny()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType),
                effect: @"""[parameters('effect')]""",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [""audit"", ""Deny""] } }");

            NSGSecurityRuleChildOnlyDenyCoverageTests.AssertSingleFinding(results: results);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_UnconstrainedEffectParameter()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType),
                effect: @"""[parameters('effect')]""",
                parameters: @"{ ""effect"": { ""type"": ""String"" } }");

            NSGSecurityRuleChildOnlyDenyCoverageTests.AssertSingleFinding(results: results);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_RepeatedChildSelections_FiresOnce()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: @"{ ""allOf"": [" +
                    NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType) + ", " +
                    NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType) +
                    @"] }");

            NSGSecurityRuleChildOnlyDenyCoverageTests.AssertSingleFinding(
                results: results,
                linePosition: 124,
                path: "properties.policyRule.if.allOf[0].equals");
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_ParentAlsoSelected()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: @"{ ""allOf"": [" +
                    NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType) + ", " +
                    NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ParentResourceType.ToUpperInvariant()) +
                    @"] }");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_ParentAndChildInSameInCondition()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: @"{ ""field"": ""type"", ""in"": [""" + ChildResourceType + @""", """ + ParentResourceType + @"""] }");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_ParentOnly()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ParentResourceType));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_ChildWithIndeterminateTypeBranch()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: @"{ ""anyOf"": [" +
                    NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType) +
                    @", { ""field"": ""type"", ""notEquals"": ""Microsoft.Storage/storageAccounts"" }] }");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_ChildUnderOddNot()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: @"{ ""not"": " +
                    NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType) +
                    @" }");

            results.Should().BeEmpty();
        }

        [Theory]
        [MemberData(nameof(UnsupportedTypeConditions))]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_UnsupportedTypeCondition(string condition)
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(condition: condition);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("denyAction")]
        [InlineData("modify")]
        [InlineData("append")]
        [InlineData("audit")]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_NonDenyLiteralEffect(string effect)
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType),
                effect: @"""" + effect + @"""");

            results.Should().BeEmpty();
        }

        [Theory]
        [MemberData(nameof(NonDenyParameterizedEffects))]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_EffectCannotSelectDeny(
            string parameters,
            string effect)
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(ChildResourceType),
                effect: effect,
                parameters: parameters);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleChildOnlyDenyCoverage_UnrelatedChildType()
        {
            var results = NSGSecurityRuleChildOnlyDenyCoverageTests.Lint(
                condition: NSGSecurityRuleChildOnlyDenyCoverageTests.EqualsType(
                    resourceType: "Microsoft.Compute/virtualMachines/extensions"));

            results.Should().BeEmpty();
        }

        private static LinterOutput[] Lint(
            string condition,
            string effect = @"""deny""",
            string parameters = "{}")
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NSGSecurityRuleChildOnlyDenyCoverage(),
                },
                metadata: MockMetadata);

            return linter.Lint(NSGSecurityRuleChildOnlyDenyCoverageTests.PolicyDefinition(
                condition: condition,
                effect: effect,
                parameters: parameters));
        }

        private static string PolicyDefinition(string condition, string effect, string parameters) => @"
                {
                  ""properties"": {
                    ""parameters"": " + parameters + @",
                    ""policyRule"": {
                      ""if"": " + condition + @",
                      ""then"": {
                        ""effect"": " + effect + @"
                      }
                    }
                  }
                }";

        private static string EqualsType(string resourceType) =>
            @"{ ""field"": ""type"", ""equals"": """ + resourceType + @""" }";

        private static void AssertSingleFinding(
            LinterOutput[] results,
            int linePosition = 112,
            string path = "properties.policyRule.if.equals")
        {
            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "nsg-security-rule-child-only-deny-coverage",
                Title: "NSG Security Rule Child-Only Deny Coverage",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: linePosition,
                Path: path,
                Description: "This deny-capable definition covers the child security-rule request path but not changes submitted through the parent NSG 'securityRules' collection. Add equivalent parent coverage in this or another policy.");

            results.Should().ContainEquivalentOf(output);
        }
    }
}
