namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="UnguardedTryGetOperatorValue"/> rule.
    /// </summary>
    public class UnguardedTryGetOperatorValueTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        private static PolicyLinter CreateLinter()
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnguardedTryGetOperatorValue()
                },
                metadata: MockMetadata);
        }

        [Fact]
        public void RuleTests_UnguardedTryGetOperatorValue_EqualsWithUnguardedTryGet_Violation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""[tryGet(field('tags'), 'environment')]""
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
                RuleIdentifier: "unguarded-tryget-operator-value",
                Title: "Unguarded tryGet Operator Value",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 74,
                Path: "properties.policyRule.if.equals",
                Description: "The 'equals' operator's value is a 'tryGet(...)' expression, which returns null when the property is missing. Policy evaluation fails when an operator value evaluates to null. Wrap the expression in 'coalesce(..., <fallback>)' so the value is never null.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_UnguardedTryGetOperatorValue_NotEqualsWithUnguardedTryGet_Violation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""notEquals"": ""[tryGet(field('tags'), 'environment')]""
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
                RuleIdentifier: "unguarded-tryget-operator-value",
                Title: "Unguarded tryGet Operator Value",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 77,
                Path: "properties.policyRule.if.notEquals",
                Description: "The 'notEquals' operator's value is a 'tryGet(...)' expression, which returns null when the property is missing. Policy evaluation fails when an operator value evaluates to null. Wrap the expression in 'coalesce(..., <fallback>)' so the value is never null.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_UnguardedTryGetOperatorValue_CaseInsensitiveFunctionName_Violation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""[TRYGET(field('tags'), 'environment')]""
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
                RuleIdentifier: "unguarded-tryget-operator-value",
                Title: "Unguarded tryGet Operator Value",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 74,
                Path: "properties.policyRule.if.equals",
                Description: "The 'equals' operator's value is a 'tryGet(...)' expression, which returns null when the property is missing. Policy evaluation fails when an operator value evaluates to null. Wrap the expression in 'coalesce(..., <fallback>)' so the value is never null.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("like", 72)]
        [InlineData("notLike", 75)]
        [InlineData("in", 70)]
        [InlineData("notIn", 73)]
        [InlineData("contains", 76)]
        [InlineData("notContains", 79)]
        [InlineData("containsKey", 79)]
        [InlineData("notContainsKey", 82)]
        [InlineData("exists", 74)]
        [InlineData("match", 73)]
        [InlineData("notMatch", 76)]
        [InlineData("greater", 75)]
        [InlineData("greaterOrEquals", 83)]
        [InlineData("less", 72)]
        [InlineData("lessOrEquals", 80)]
        [InlineData("matchInsensitively", 86)]
        [InlineData("notMatchInsensitively", 89)]
        public void RuleTests_UnguardedTryGetOperatorValue_AdditionalOperator(
            string operatorName,
            int linePosition)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""name"",
                        ""{operatorName}"": ""[tryGet(field('tags'), 'environment')]""
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "unguarded-tryget-operator-value",
                Title: "Unguarded tryGet Operator Value",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: linePosition,
                Path: "properties.policyRule.if." + operatorName,
                Description: $"The '{operatorName}' operator's value is a 'tryGet(...)' expression, which returns null when the property is missing. Policy evaluation fails when an operator value evaluates to null. Wrap the expression in 'coalesce(..., <fallback>)' so the value is never null.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_UnguardedTryGetOperatorValue_TryGetGuardedByCoalesce_NoViolation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""[coalesce(tryGet(field('tags'), 'environment'), '')]""
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
        public void RuleTests_UnguardedTryGetOperatorValue_TryGetNotOutermostFunction_NoViolation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""[concat(tryGet(field('tags'), 'environment'), '-suffix')]""
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
        public void RuleTests_UnguardedTryGetOperatorValue_LiteralValue_NoViolation()
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
        public void RuleTests_UnguardedTryGetOperatorValue_FieldReferenceValue_NoViolation()
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

        [Fact]
        public void RuleTests_UnguardedTryGetOperatorValue_ExpressionNestedInArray_NoViolation()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""in"": [
                          ""[tryGet(field('tags'), 'environment')]""
                        ]
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
    }
}
