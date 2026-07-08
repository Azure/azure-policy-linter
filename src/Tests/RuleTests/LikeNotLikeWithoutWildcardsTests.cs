namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="LikeNotLikeWithoutWildcards"/> rule.
    /// </summary>
    public class LikeNotLikeWithoutWildcardsTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        void LinterTests_LikeNotLikeWithoutWildcards_LikeWithoutWildcard()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LikeNotLikeWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": ""Microsoft.Compute/virtualMachines""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "like-notlike-without-wildcards",
                Title: "like/notLike Without Wildcards",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 67,
                Path: "properties.policyRule.if.like",
                Description: "The condition uses the 'like' operator with value 'Microsoft.Compute/virtualMachines' which contains no wildcards (* or ?). Use 'equals' instead to better reflect the intention of exact matching.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_LikeNotLikeWithoutWildcards_NotLikeWithoutWildcard()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LikeNotLikeWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""notLike"": ""Microsoft.Compute/virtualMachines""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "like-notlike-without-wildcards",
                Title: "like/notLike Without Wildcards",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 70,
                Path: "properties.policyRule.if.notLike",
                Description: "The condition uses the 'notLike' operator with value 'Microsoft.Compute/virtualMachines' which contains no wildcards (* or ?). Use 'notEquals' instead to better reflect the intention of exact matching.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("like", "Microsoft.Compute/*")]
        [InlineData("like", "Microsoft.Compute/virtual?achines")]
        [InlineData("notLike", "Microsoft.*/storageAccounts")]
        [InlineData("notLike", "Microsoft.Compute/virtual?achines")]
        void LinterTests_LikeNotLikeWithoutWildcards_WithWildcards_NoViolation(string operatorName, string operandValue)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LikeNotLikeWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""type"",
                        ""{operatorName}"": ""{operandValue}""
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_LikeNotLikeWithoutWildcards_ParameterizedValue_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LikeNotLikeWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""parameters"": {
                      ""pattern"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": ""[parameters('pattern')]""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("equals")]
        [InlineData("notEquals")]
        [InlineData("contains")]
        [InlineData("in")]
        void LinterTests_LikeNotLikeWithoutWildcards_OtherOperators_NoViolation(string operatorName)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LikeNotLikeWithoutWildcards()
                },
                metadata: TypeMetadata);

            var operandValue = operatorName == "in"
                ? @"[""Microsoft.Compute/virtualMachines""]"
                : @"""Microsoft.Compute/virtualMachines""";

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""type"",
                        ""{operatorName}"": {operandValue}
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
