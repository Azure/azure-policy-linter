namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="NSGSecurityRuleParentOnlyDenyCoverage"/> rule.
    /// </summary>
    public class NSGSecurityRuleParentOnlyDenyCoverageTests
    {
        private const string ParentTypeCondition =
            @"{ ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" }";

        private const string ParentAliasCondition =
            @"{ ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }";

        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_LiteralDenyDirectField()
        {
            var ifCondition = $@"{{ ""allOf"": [ {ParentTypeCondition}, {ParentAliasCondition} ] }}";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(ifCondition: ifCondition);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_CountField()
        {
            var ifCondition = $@"{{
                ""allOf"": [
                    {ParentTypeCondition},
                    {{
                        ""count"": {{
                            ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*]""
                        }},
                        ""greater"": 0
                    }}
                ]
            }}";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(ifCondition: ifCondition);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_FieldFunction()
        {
            var ifCondition = $@"{{
                ""allOf"": [
                    {ParentTypeCondition},
                    {{
                        ""value"": ""[field('Microsoft.Network/networkSecurityGroups/securityRules[*].access')]"",
                        ""equals"": ""Deny""
                    }}
                ]
            }}";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(ifCondition: ifCondition);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_CurrentFunction()
        {
            var ifCondition = $@"{{
                ""allOf"": [
                    {ParentTypeCondition},
                    {{
                        ""count"": {{
                            ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*]"",
                            ""where"": {{
                                ""value"": ""[current('Microsoft.Network/networkSecurityGroups/securityRules[*].access')]"",
                                ""equals"": ""Deny""
                            }}
                        }},
                        ""greater"": 0
                    }}
                ]
            }}";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(ifCondition: ifCondition);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_CaseInsensitive()
        {
            var ifCondition = @"{
                ""allOf"": [
                    {
                        ""field"": ""TYPE"",
                        ""equals"": ""MICROSOFT.NETWORK/NETWORKSECURITYGROUPS""
                    },
                    {
                        ""field"": ""microsoft.network/NETWORKSECURITYGROUPS/SECURITYRULES[*].ACCESS"",
                        ""equals"": ""Deny""
                    }
                ]
            }";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(
                ifCondition: ifCondition,
                effect: @"""DENY""");
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_TypeIn()
        {
            var ifCondition = $@"{{
                ""allOf"": [
                    {{
                        ""field"": ""type"",
                        ""in"": [
                            ""Microsoft.Network/networkSecurityGroups"",
                            ""Microsoft.Network/virtualNetworks""
                        ]
                    }},
                    {ParentAliasCondition}
                ]
            }}";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(ifCondition: ifCondition);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_DoubleNotType()
        {
            var ifCondition = $@"{{
                ""allOf"": [
                    {{
                        ""not"": {{
                            ""not"": {ParentTypeCondition}
                        }}
                    }},
                    {ParentAliasCondition}
                ]
            }}";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(ifCondition: ifCondition);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_EffectParameterAllowsDeny()
        {
            var ifCondition = $@"{{ ""allOf"": [ {ParentTypeCondition}, {ParentAliasCondition} ] }}";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(
                ifCondition: ifCondition,
                effect: @"""[parameters('effect')]""",
                parameters: @"{
                    ""effect"": {
                        ""type"": ""String"",
                        ""allowedValues"": [ ""audit"", ""deny"" ]
                    }
                }");
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_UnconstrainedEffectParameter()
        {
            var ifCondition = $@"{{ ""allOf"": [ {ParentTypeCondition}, {ParentAliasCondition} ] }}";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(
                ifCondition: ifCondition,
                effect: @"""[parameters('effect')]""",
                parameters: @"{
                    ""effect"": {
                        ""type"": ""String""
                    }
                }");
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_RepeatedAliasesOneFinding()
        {
            var ifCondition = $@"{{
                ""allOf"": [
                    {ParentTypeCondition},
                    {ParentAliasCondition},
                    {{
                        ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].priority"",
                        ""greater"": 100
                    }}
                ]
            }}";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(ifCondition: ifCondition);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_IndexedModeChildTypeMentionedStillFires()
        {
            var ifCondition = @"{ ""allOf"": [
                { ""field"": ""type"", ""in"": [
                    ""Microsoft.Network/networkSecurityGroups"",
                    ""Microsoft.Network/networkSecurityGroups/securityRules""
                ] },
                { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
            ] }";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(ifCondition: ifCondition);
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_AllModeParentAliasMakesCombinedTypeBranchIneffective()
        {
            var ifCondition = @"{ ""allOf"": [
                { ""field"": ""type"", ""in"": [
                    ""Microsoft.Network/networkSecurityGroups"",
                    ""Microsoft.Network/networkSecurityGroups/securityRules""
                ] },
                { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
            ] }";

            NSGSecurityRuleParentOnlyDenyCoverageTests.AssertFinding(
                ifCondition: ifCondition,
                mode: "All");
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_AllModeEffectiveChildBranch()
        {
            var ifCondition = @"{ ""anyOf"": [
                { ""allOf"": [
                    { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" },
                    { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
                ] },
                { ""allOf"": [
                    { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups/securityRules"" },
                    { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules/access"", ""equals"": ""Deny"" }
                ] }
            ] }";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                mode: "All");

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups/securityRules"" },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/subnets[*].name"", ""exists"": ""true"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/defaultSecurityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules/access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""not"": { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" } },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""like"": ""Microsoft.Network/networkSecurityGroups*"" },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""notEquals"": ""Microsoft.Network/networkSecurityGroups"" },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""notIn"": [ ""Microsoft.Network/networkSecurityGroups"" ] },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""equals"": ""[parameters('resourceType')]"" },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""[parameters('typeField')]"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""in"": [
                ""Microsoft.Network/networkSecurityGroups"",
                ""[parameters('resourceType')]""
            ] },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""equals"": """" },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""in"": [] },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" },
            { ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*]Access"", ""equals"": ""Deny"" }
        ] }")]
        [InlineData(@"{ ""allOf"": [
            { ""field"": ""type"", ""equals"": ""Microsoft.Network/networkSecurityGroups"" },
            { ""field"": ""[parameters('securityRuleAlias')]"", ""equals"": ""Deny"" }
        ] }")]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_NonApplicableIfConditions(string ifCondition)
        {
            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                parameters: @"{
                    ""resourceType"": {
                        ""type"": ""String""
                    },
                    ""typeField"": {
                        ""type"": ""String""
                    },
                    ""securityRuleAlias"": {
                        ""type"": ""String""
                    }
                }");

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData(@"""audit""")]
        [InlineData(@"""denyAction""")]
        [InlineData(@"""modify""")]
        [InlineData(@"""append""")]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_NonDenyLiteralEffects(string effect)
        {
            var ifCondition = $@"{{ ""allOf"": [ {ParentTypeCondition}, {ParentAliasCondition} ] }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                effect: effect);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData(@"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [ ""audit"" ] } }")]
        [InlineData(@"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [] } }")]
        [InlineData(@"{ ""effect"": { ""type"": ""Array"" } }")]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_NonDenyCapableEffectParameters(string parameters)
        {
            var ifCondition = $@"{{ ""allOf"": [ {ParentTypeCondition}, {ParentAliasCondition} ] }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                effect: @"""[parameters('effect')]""",
                parameters: parameters);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NSGSecurityRuleParentOnlyDenyCoverage_ComplexEffect()
        {
            var ifCondition = $@"{{ ""allOf"": [ {ParentTypeCondition}, {ParentAliasCondition} ] }}";

            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                effect: @"""[if(equals(parameters('effect'), 'deny'), 'deny', 'audit')]""",
                parameters: @"{
                    ""effect"": {
                        ""type"": ""String"",
                        ""allowedValues"": [ ""audit"", ""deny"" ]
                    }
                }");

            results.Should().BeEmpty();
        }

        private static void AssertFinding(
            string ifCondition,
            string effect = @"""deny""",
            string parameters = "{}",
            string mode = "Indexed")
        {
            var results = NSGSecurityRuleParentOnlyDenyCoverageTests.Lint(
                ifCondition: ifCondition,
                effect: effect,
                parameters: parameters,
                mode: mode);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "nsg-security-rule-parent-only-deny-coverage",
                Title: "NSG Security Rule Parent-Only Deny Coverage",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 34 + JToken.Parse(effect).ToString(Formatting.None).Length,
                Path: "properties.policyRule.then.effect",
                Description: "This deny-capable definition covers security rules submitted in the parent NSG collection but not independently deployed child security-rule requests. Add equivalent child coverage in this or another policy.");

            results.Should().ContainEquivalentOf(output);
        }

        private static LinterOutput[] Lint(
            string ifCondition,
            string effect = @"""deny""",
            string parameters = "{}",
            string mode = "Indexed")
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NSGSecurityRuleParentOnlyDenyCoverage(),
                },
                metadata: NSGSecurityRuleParentOnlyDenyCoverageTests.MockMetadata);

            var compactIfCondition = JToken.Parse(ifCondition).ToString(Formatting.None);
            var compactEffect = JToken.Parse(effect).ToString(Formatting.None);
            var compactParameters = JToken.Parse(parameters).ToString(Formatting.None);
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""mode"": ""{mode}"",
                    ""parameters"": {compactParameters},
                    ""policyRule"": {{
                      ""if"": {compactIfCondition},
                      ""then"": {{
                        ""effect"": {compactEffect}
                      }}
                    }}
                  }}
                }}";

            return linter.Lint(policyDefinition);
        }
    }
}
