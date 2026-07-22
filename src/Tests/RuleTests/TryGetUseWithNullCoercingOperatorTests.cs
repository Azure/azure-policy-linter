namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="TryGetUseWithNullCoercingOperator"/> rule.
    /// </summary>
    public class TryGetUseWithNullCoercingOperatorTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        private static PolicyLinter CreateLinter() => new PolicyLinter(
            rules: new ILinterRule[] { new TryGetUseWithNullCoercingOperator() },
            metadata: MockMetadata);

        [Fact]
        public void RuleTests_TryGetUseWithNullCoercingOperator_EqualsOperator()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[tryGet(field('properties'), 'tier')]"",
                        ""equals"": ""premium""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "tryget-use-with-null-coercing-operator",
                Title: "tryGet Use with Null-Coercing Operator",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 72,
                Path: "properties.policyRule.if.value",
                Description: "The value condition compares the 'tryGet' expression '[tryGet(field('properties'), 'tier')]' with 'equals'. When 'tryGet' returns null, the operator coerces it to an empty string before evaluating the condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_TryGetUseWithNullCoercingOperator_NotEqualsOperator()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[tryGet(field('properties'), 'tier')]"",
                        ""notEquals"": ""premium""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "tryget-use-with-null-coercing-operator",
                Title: "tryGet Use with Null-Coercing Operator",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 72,
                Path: "properties.policyRule.if.value",
                Description: "The value condition compares the 'tryGet' expression '[tryGet(field('properties'), 'tier')]' with 'notEquals'. When 'tryGet' returns null, the operator coerces it to an empty string before evaluating the condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("in", "[\"premium\"]")]
        [InlineData("notIn", "[\"premium\"]")]
        [InlineData("like", "\"prem*\"")]
        [InlineData("notLike", "\"prem*\"")]
        [InlineData("contains", "\"premium\"")]
        [InlineData("notContains", "\"premium\"")]
        [InlineData("match", "\"premium\"")]
        [InlineData("notMatch", "\"premium\"")]
        [InlineData("matchInsensitively", "\"premium\"")]
        [InlineData("notMatchInsensitively", "\"premium\"")]
        public void RuleTests_TryGetUseWithNullCoercingOperator_AdditionalNullCoercingOperator(
            string @operator,
            string comparisonValue)
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[tryGet(field('properties'), 'tier')]"",
                        ""__OPERATOR__"": __VALUE__
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            policyDefinition = policyDefinition
                .Replace("__OPERATOR__", @operator)
                .Replace("__VALUE__", comparisonValue);

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "tryget-use-with-null-coercing-operator",
                Title: "tryGet Use with Null-Coercing Operator",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 72,
                Path: "properties.policyRule.if.value",
                Description: $"The value condition compares the 'tryGet' expression '[tryGet(field('properties'), 'tier')]' with '{@operator}'. When 'tryGet' returns null, the operator coerces it to an empty string before evaluating the condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_TryGetUseWithNullCoercingOperator_MixedCaseFunctionName()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[TrYgEt(field('properties'), 'tier')]"",
                        ""equals"": ""premium""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "tryget-use-with-null-coercing-operator",
                Title: "tryGet Use with Null-Coercing Operator",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 72,
                Path: "properties.policyRule.if.value",
                Description: "The value condition compares the 'tryGet' expression '[TrYgEt(field('properties'), 'tier')]' with 'equals'. When 'tryGet' returns null, the operator coerces it to an empty string before evaluating the condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_TryGetUseWithNullCoercingOperator_CoalesceGuarded_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[coalesce(tryGet(field('properties'), 'tier'), 'none')]"",
                        ""equals"": ""premium""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            // The 'tryGet' is wrapped in 'coalesce', so the comparison has a defined operand.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_TryGetUseWithNullCoercingOperator_LiteralValue_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""premium"",
                        ""equals"": ""premium""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_TryGetUseWithNullCoercingOperator_ExpressionNestedInObject_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": {
                          ""tier"": ""[tryGet(field('properties'), 'tier')]""
                        },
                        ""equals"": ""premium""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_TryGetUseWithNullCoercingOperator_NonTryGetFunction_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[concat(field('name'), '-suffix')]"",
                        ""equals"": ""premium""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_TryGetUseWithNullCoercingOperator_TryGetNestedInOtherFunction_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[concat(tryGet(field('properties'), 'tier'), '-x')]"",
                        ""equals"": ""premium""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            // The outermost function is 'concat', not 'tryGet' - out of scope.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_TryGetUseWithNullCoercingOperator_NonNullCoercingOperator_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[tryGet(field('properties'), 'tier')]"",
                        ""greater"": 5
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_TryGetUseWithNullCoercingOperator_FieldConditionWithTryGetValue_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""[tryGet(field('properties'), 'tier')]""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = TryGetUseWithNullCoercingOperatorTests.CreateLinter().Lint(policyDefinition);

            // A 'field' condition is out of scope; the right-hand 'tryGet' is a separate concern.
            results.Should().BeEmpty();
        }
    }
}
