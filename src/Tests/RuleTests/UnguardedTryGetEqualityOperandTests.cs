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
    /// Tests for the <see cref="UnguardedTryGetEqualityOperand"/> rule.
    /// </summary>
    public class UnguardedTryGetEqualityOperandTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        private static PolicyLinter CreateLinter()
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnguardedTryGetEqualityOperand()
                },
                metadata: TypeMetadata);
        }

        [Fact]
        public void RuleTests_UnguardedTryGetEqualityOperand_EqualsWithUnguardedTryGet_Violation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""[tryGet(field('properties'), 'displayName')]""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "unguarded-tryget-equality-operand",
                Title: "Unguarded tryGet Equality Operand",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 80,
                Path: "properties.policyRule.if.equals",
                Description: "The 'equals' operator's value is a 'tryGet(...)' expression, which returns null when the property is missing. The 'equals' operator throws on a null value at evaluation time. Wrap the expression in 'coalesce(..., <fallback>)' so the value is never null.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_UnguardedTryGetEqualityOperand_NotEqualsWithUnguardedTryGet_Violation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""notEquals"": ""[tryGet(field('properties'), 'displayName')]""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "unguarded-tryget-equality-operand",
                Title: "Unguarded tryGet Equality Operand",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 83,
                Path: "properties.policyRule.if.notEquals",
                Description: "The 'notEquals' operator's value is a 'tryGet(...)' expression, which returns null when the property is missing. The 'notEquals' operator throws on a null value at evaluation time. Wrap the expression in 'coalesce(..., <fallback>)' so the value is never null.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_UnguardedTryGetEqualityOperand_CaseInsensitiveFunctionName_Violation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""[TRYGET(field('properties'), 'displayName')]""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
        }

        [Fact]
        public void RuleTests_UnguardedTryGetEqualityOperand_TryGetGuardedByCoalesce_NoViolation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""[coalesce(tryGet(field('properties'), 'displayName'), '')]""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedTryGetEqualityOperand_TryGetNotOutermostFunction_NoViolation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""[concat(tryGet(field('properties'), 'displayName'), '-suffix')]""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedTryGetEqualityOperand_LiteralValue_NoViolation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""my-resource-name""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedTryGetEqualityOperand_FieldReferenceValue_NoViolation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""[field('location')]""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("like")]
        [InlineData("notLike")]
        [InlineData("contains")]
        public void RuleTests_UnguardedTryGetEqualityOperand_OtherOperators_NoViolation(string operatorName)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""name"",
                        ""{operatorName}"": ""[tryGet(field('properties'), 'displayName')]""
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
