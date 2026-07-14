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
    /// Tests for the <see cref="SimplifyMultipleEqualsToIn"/> rule.
    /// </summary>
    public class SimplifyMultipleEqualsToInTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_SimplifyMultipleEqualsToIn_Violation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleEqualsToIn()
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "simplify-multiple-equals-to-in",
                Title: "Simplify Multiple Equals to In",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.anyOf[0]",
                Description: "The 'anyOf' contains 2 'equals' conditions on field 'type' that can be simplified to a single 'in' condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_SimplifyMultipleEqualsToIn_DifferentFields_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleEqualsToIn()
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
        public void RuleTests_SimplifyMultipleEqualsToIn_SingleEquals_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleEqualsToIn()
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
                            ""field"": ""location"",
                            ""notEquals"": ""westus""
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
        public void RuleTests_SimplifyMultipleEqualsToIn_AlreadyUsesIn_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleEqualsToIn()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""in"": [
                          ""Microsoft.Compute/virtualMachines"",
                          ""Microsoft.Storage/storageAccounts""
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
        public void RuleTests_SimplifyMultipleEqualsToIn_ThreeEqualsOnSameField()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleEqualsToIn()
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
                          },
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Network/virtualNetworks""
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
                RuleIdentifier: "simplify-multiple-equals-to-in",
                Title: "Simplify Multiple Equals to In",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.anyOf[0]",
                Description: "The 'anyOf' contains 3 'equals' conditions on field 'type' that can be simplified to a single 'in' condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_SimplifyMultipleEqualsToIn_MultipleFieldGroups_Violation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleEqualsToIn()
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
                          },
                          {
                            ""field"": ""location"",
                            ""equals"": ""eastus""
                          },
                          {
                            ""field"": ""location"",
                            ""equals"": ""westus""
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

            var typeFinding = new LinterOutput(
                RuleIdentifier: "simplify-multiple-equals-to-in",
                Title: "Simplify Multiple Equals to In",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.anyOf[0]",
                Description: "The 'anyOf' contains 2 'equals' conditions on field 'type' that can be simplified to a single 'in' condition.");

            var locationFinding = new LinterOutput(
                RuleIdentifier: "simplify-multiple-equals-to-in",
                Title: "Simplify Multiple Equals to In",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 27,
                Path: "properties.policyRule.if.anyOf[2]",
                Description: "The 'anyOf' contains 2 'equals' conditions on field 'location' that can be simplified to a single 'in' condition.");

            results.Should().ContainEquivalentOf(typeFinding);
            results.Should().ContainEquivalentOf(locationFinding);
        }

        [Fact]
        public void RuleTests_SimplifyMultipleEqualsToIn_AllOf_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleEqualsToIn()
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
        public void RuleTests_SimplifyMultipleEqualsToIn_ExpressionFieldValue_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleEqualsToIn()
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
                            ""field"": ""[parameters('fieldName')]"",
                            ""equals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""[parameters('fieldName')]"",
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
        public void RuleTests_SimplifyMultipleEqualsToIn_NestedChildQuantifier_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleEqualsToIn()
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
                            ""allOf"": [
                              {
                                ""field"": ""type"",
                                ""equals"": ""Microsoft.Compute/virtualMachines""
                              }
                            ]
                          },
                          {
                            ""allOf"": [
                              {
                                ""field"": ""type"",
                                ""equals"": ""Microsoft.Storage/storageAccounts""
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

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_SimplifyMultipleEqualsToIn_CaseInsensitiveFieldMatching_Violation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleEqualsToIn()
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
                            ""field"": ""Type"",
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "simplify-multiple-equals-to-in",
                Title: "Simplify Multiple Equals to In",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.anyOf[0]",
                Description: "The 'anyOf' contains 2 'equals' conditions on field 'Type' that can be simplified to a single 'in' condition.");

            results.Should().ContainEquivalentOf(output);
        }
    }
}
