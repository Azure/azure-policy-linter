namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="UnguardedTryGetInComparedValue"/> rule.
    /// </summary>
    public class UnguardedTryGetInComparedValueTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        private static PolicyLinter CreateLinter() => new PolicyLinter(
            rules: new ILinterRule[] { new UnguardedTryGetInComparedValue() },
            metadata: MockMetadata);

        [Fact]
        public void RuleTests_UnguardedTryGetInComparedValue_EqualsOperator()
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

            var results = UnguardedTryGetInComparedValueTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "unguarded-tryget-in-compared-value",
                Title: "Unguarded tryGet in Compared Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 72,
                Path: "properties.policyRule.if.value",
                Description: "The value condition compares the unguarded 'tryGet' expression '[tryGet(field('properties'), 'tier')]' with 'equals'. 'tryGet' returns null when a path segment is missing, which is coerced to empty string, so the condition silently never matches. Wrap the 'tryGet' in 'coalesce' with a fallback value.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_UnguardedTryGetInComparedValue_NotEqualsOperator()
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

            var results = UnguardedTryGetInComparedValueTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("unguarded-tryget-in-compared-value");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        public void RuleTests_UnguardedTryGetInComparedValue_CoalesceGuarded_ShouldNotFire()
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

            var results = UnguardedTryGetInComparedValueTests.CreateLinter().Lint(policyDefinition);

            // The 'tryGet' is wrapped in 'coalesce', so the comparison has a defined operand.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedTryGetInComparedValue_LiteralValue_ShouldNotFire()
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

            var results = UnguardedTryGetInComparedValueTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedTryGetInComparedValue_NonTryGetFunction_ShouldNotFire()
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

            var results = UnguardedTryGetInComparedValueTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedTryGetInComparedValue_TryGetNestedInOtherFunction_ShouldNotFire()
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

            var results = UnguardedTryGetInComparedValueTests.CreateLinter().Lint(policyDefinition);

            // The outermost function is 'concat', not 'tryGet' - out of scope.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedTryGetInComparedValue_NonEqualityOperator_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[tryGet(field('properties'), 'tier')]"",
                        ""like"": ""prem*""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = UnguardedTryGetInComparedValueTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedTryGetInComparedValue_FieldConditionWithTryGetValue_ShouldNotFire()
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

            var results = UnguardedTryGetInComparedValueTests.CreateLinter().Lint(policyDefinition);

            // A 'field' condition is out of scope; the right-hand 'tryGet' is a separate concern.
            results.Should().BeEmpty();
        }
    }
}
