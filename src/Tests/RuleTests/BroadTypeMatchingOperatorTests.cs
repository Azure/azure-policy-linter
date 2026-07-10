namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="BroadTypeMatchingOperator"/> rule.
    /// </summary>
    public class BroadTypeMatchingOperatorTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_BroadTypeMatchingOperator_ContainsOperator()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new BroadTypeMatchingOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""contains"": ""Microsoft.Storage""
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
                RuleIdentifier: "broad-type-matching-operator",
                Title: "Broad Type Matching Operator",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 55,
                Path: "properties.policyRule.if.contains",
                Description: "The 'type' field is compared with the broad 'contains' operator, which can match resource types you did not intend to target. Use 'equals' or 'in' to target resource types explicitly.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_BroadTypeMatchingOperator_LikeOperator()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new BroadTypeMatchingOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": ""Microsoft.Storage/*""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("broad-type-matching-operator");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        public void RuleTests_BroadTypeMatchingOperator_MatchOperator()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new BroadTypeMatchingOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""match"": ""Microsoft.*""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("broad-type-matching-operator");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        public void RuleTests_BroadTypeMatchingOperator_MatchInsensitivelyOperator()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new BroadTypeMatchingOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""matchInsensitively"": ""microsoft\\.storage/.*""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("broad-type-matching-operator");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        public void RuleTests_BroadTypeMatchingOperator_ExactMatchOperator_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new BroadTypeMatchingOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""type"",
                            ""in"": [
                              ""Microsoft.Storage/storageAccounts"",
                              ""Microsoft.Compute/virtualMachines""
                            ]
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // 'equals' and 'in' target resource types explicitly - nothing to flag.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BroadTypeMatchingOperator_BroadOperatorWithExplicitResourceType()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new BroadTypeMatchingOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""type"",
                            ""like"": ""Microsoft.Compute/*""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // Only the 'like' condition is flagged; the 'equals' condition is fine.
            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("broad-type-matching-operator");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        public void RuleTests_BroadTypeMatchingOperator_BroadOperatorOnNonTypeField_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new BroadTypeMatchingOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""name"",
                            ""like"": ""prod-*""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // Broad operator is on the 'name' field, not 'type' - not flagged.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BroadTypeMatchingOperator_MultipleBroadOperators_FiresPerCondition()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new BroadTypeMatchingOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""anyOf"": [
                          {
                            ""field"": ""type"",
                            ""contains"": ""Storage""
                          },
                          {
                            ""field"": ""type"",
                            ""match"": ""Microsoft\\.Compute/.*""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // Each broad-operator 'type' condition is an independent finding.
            results.Should().HaveCount(2);
            results.Should().OnlyContain(output => output.RuleIdentifier == "broad-type-matching-operator");
        }

        [Fact]
        public void RuleTests_BroadTypeMatchingOperator_NoOperator_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new BroadTypeMatchingOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""in"": [""Microsoft.Storage/storageAccounts""]
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
    }
}
