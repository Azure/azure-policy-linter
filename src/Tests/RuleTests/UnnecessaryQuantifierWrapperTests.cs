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
    /// Tests for the <see cref="UnnecessaryQuantifierWrapper"/> rule.
    /// </summary>
    public class UnnecessaryQuantifierWrapperTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_UnnecessaryQuantifierWrapper_AllOfSingleExpression()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Compute/virtualMachines""
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "unnecessary-quantifier-wrapper",
                Title: "Unnecessary Quantifier Wrapper",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 34,
                Path: "properties.policyRule.if.allOf",
                Description: "The 'allOf' contains a single expression and can be removed. Use the inner expression directly.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_UnnecessaryQuantifierWrapper_AnyOfSingleExpression()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""anyOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Compute/virtualMachines""
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "unnecessary-quantifier-wrapper",
                Title: "Unnecessary Quantifier Wrapper",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 34,
                Path: "properties.policyRule.if.anyOf",
                Description: "The 'anyOf' contains a single expression and can be removed. Use the inner expression directly.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_UnnecessaryQuantifierWrapper_AllOfMultipleExpressions_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""location"",
                            ""equals"": ""eastus""
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

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnnecessaryQuantifierWrapper_AnyOfMultipleExpressions_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""anyOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
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

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnnecessaryQuantifierWrapper_NoQuantifier_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Compute/virtualMachines""
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

        [Fact]
        public void RuleTests_UnnecessaryQuantifierWrapper_NotQuantifier_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""field"": ""type"",
                          ""equals"": ""Microsoft.Compute/virtualMachines""
                        }
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

        [Fact]
        public void RuleTests_UnnecessaryQuantifierWrapper_EmptyAllOf_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": []
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

        [Fact]
        public void RuleTests_UnnecessaryQuantifierWrapper_EmptyAnyOf_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""anyOf"": []
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

        [Fact]
        public void RuleTests_UnnecessaryQuantifierWrapper_NestedSingleChildChain_ReportedAtEachLevel()
        {
            // A chain of single-child quantifiers is reported per level by this rule; the
            // nested-same-type-quantifiers rule defers to it and stays silent on this shape.
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper(),
                    new NestedSameTypeQuantifiersShouldBeFlattened()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""allOf"": [
                              {
                                ""field"": ""type"",
                                ""equals"": ""Microsoft.Compute/virtualMachines""
                              }
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

            results.Should().HaveCount(2);
            results.Should().OnlyContain(output => output.RuleIdentifier == "unnecessary-quantifier-wrapper");

            var outer = new LinterOutput(
                RuleIdentifier: "unnecessary-quantifier-wrapper",
                Title: "Unnecessary Quantifier Wrapper",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 34,
                Path: "properties.policyRule.if.allOf",
                Description: "The 'allOf' contains a single expression and can be removed. Use the inner expression directly.");

            var inner = new LinterOutput(
                RuleIdentifier: "unnecessary-quantifier-wrapper",
                Title: "Unnecessary Quantifier Wrapper",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 38,
                Path: "properties.policyRule.if.allOf[0].allOf",
                Description: "The 'allOf' contains a single expression and can be removed. Use the inner expression directly.");

            results.Should().ContainEquivalentOf(outer);
            results.Should().ContainEquivalentOf(inner);
        }
    }
}
