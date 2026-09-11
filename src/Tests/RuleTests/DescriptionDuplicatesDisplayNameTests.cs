namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="DescriptionDuplicatesDisplayName"/> rule.
    /// </summary>
    public class DescriptionDuplicatesDisplayNameTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_ExactMatch()
        {
            var results = Lint(@"
                {
                  ""properties"": {
                    ""displayName"": ""Audit storage accounts"",
                    ""description"": ""Audit storage accounts"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }");

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "description-duplicates-display-name",
                Title: "Description Duplicates Display Name",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 5,
                LinePosition: 59,
                Path: "properties.description",
                Description: "The description repeats the display name and adds no context. Replace it with a concise explanation of what the policy checks and why.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_CaseDifferences()
        {
            var results = Lint(@"
                {
                  ""properties"": {
                    ""displayName"": ""Audit storage accounts"",
                    ""description"": ""AUDIT STORAGE ACCOUNTS"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }");

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "description-duplicates-display-name",
                Title: "Description Duplicates Display Name",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 5,
                LinePosition: 59,
                Path: "properties.description",
                Description: "The description repeats the display name and adds no context. Replace it with a concise explanation of what the policy checks and why.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_LeadingAndTrailingWhitespace()
        {
            var results = Lint(@"
                {
                  ""properties"": {
                    ""displayName"": ""  Audit storage accounts"",
                    ""description"": ""Audit storage accounts  "",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }");

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "description-duplicates-display-name",
                Title: "Description Duplicates Display Name",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 5,
                LinePosition: 61,
                Path: "properties.description",
                Description: "The description repeats the display name and adds no context. Replace it with a concise explanation of what the policy checks and why.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_AlternateJsonPropertyCasing()
        {
            var results = Lint(@"
                {
                  ""PrOpErTiEs"": {
                    ""DiSpLaYnAmE"": ""Audit storage accounts"",
                    ""DeScRiPtIoN"": ""Audit storage accounts"",
                    ""PoLiCyRuLe"": {
                      ""If"": {
                        ""FiElD"": ""type"",
                        ""EqUaLs"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""ThEn"": {
                        ""EfFeCt"": ""audit""
                      }
                    }
                  }
                }");

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "description-duplicates-display-name",
                Title: "Description Duplicates Display Name",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 5,
                LinePosition: 59,
                Path: "properties.description",
                Description: "The description repeats the display name and adds no context. Replace it with a concise explanation of what the policy checks and why.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_DifferentValues()
        {
            var results = Lint(CreatePolicyProperties(@"
                    ""displayName"": ""Audit storage accounts"",
                    ""description"": ""Audits storage accounts that allow public network access"","));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_AbsentDisplayName()
        {
            var results = Lint(CreatePolicyProperties(@"
                    ""description"": ""Audits storage accounts"","));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_AbsentDescription()
        {
            var results = Lint(CreatePolicyProperties(@"
                    ""displayName"": ""Audit storage accounts"","));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_BlankDisplayName()
        {
            var results = Lint(CreatePolicyProperties(@"
                    ""displayName"": ""   "",
                    ""description"": ""Audit storage accounts"","));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_BlankDescription()
        {
            var results = Lint(CreatePolicyProperties(@"
                    ""displayName"": ""Audit storage accounts"",
                    ""description"": ""   "","));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_PeriodSuffix()
        {
            var results = Lint(CreatePolicyProperties(@"
                    ""displayName"": ""Audit storage accounts"",
                    ""description"": ""Audit storage accounts."","));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_PolicySuffix()
        {
            var results = Lint(CreatePolicyProperties(@"
                    ""displayName"": ""Audit storage accounts"",
                    ""description"": ""Audit storage accounts policy"","));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_DescriptionDuplicatesDisplayName_NullValues()
        {
            var results = Lint(CreatePolicyProperties(@"
                    ""displayName"": null,
                    ""description"": null,"));

            results.Should().BeEmpty();
        }

        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DescriptionDuplicatesDisplayName()
                },
                metadata: DescriptionDuplicatesDisplayNameTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }

        private static string CreatePolicyProperties(string properties) => @"
                {
                  ""properties"": {" +
                  properties + @"
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";
    }
}
