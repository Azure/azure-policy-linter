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
    /// Tests for the <see cref="SimplifyMultipleNotEqualsToNotIn"/> rule.
    /// </summary>
    public class SimplifyMultipleNotEqualsToNotInTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_Violation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
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
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""type"",
                            ""notEquals"": ""Microsoft.Storage/storageAccounts""
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
                RuleIdentifier: "simplify-multiple-notequals-to-notin",
                Title: "Simplify Multiple NotEquals to NotIn",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.allOf[0]",
                Description: "The 'allOf' contains 2 'notEquals' conditions on field 'type' that can be simplified to a single 'notIn' condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_DifferentFields_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
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
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""location"",
                            ""notEquals"": ""eastus""
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
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_SingleNotEquals_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
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
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
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

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_AlreadyUsesNotIn_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""notIn"": [
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
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_ThreeNotEqualsOnSameField()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
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
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""type"",
                            ""notEquals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""type"",
                            ""notEquals"": ""Microsoft.Network/virtualNetworks""
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
                RuleIdentifier: "simplify-multiple-notequals-to-notin",
                Title: "Simplify Multiple NotEquals to NotIn",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.allOf[0]",
                Description: "The 'allOf' contains 3 'notEquals' conditions on field 'type' that can be simplified to a single 'notIn' condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_MultipleFieldGroups_Violation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
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
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""type"",
                            ""notEquals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""location"",
                            ""notEquals"": ""eastus""
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

            results.Should().HaveCount(2);

            var typeFinding = new LinterOutput(
                RuleIdentifier: "simplify-multiple-notequals-to-notin",
                Title: "Simplify Multiple NotEquals to NotIn",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.allOf[0]",
                Description: "The 'allOf' contains 2 'notEquals' conditions on field 'type' that can be simplified to a single 'notIn' condition.");

            var locationFinding = new LinterOutput(
                RuleIdentifier: "simplify-multiple-notequals-to-notin",
                Title: "Simplify Multiple NotEquals to NotIn",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 27,
                Path: "properties.policyRule.if.allOf[2]",
                Description: "The 'allOf' contains 2 'notEquals' conditions on field 'location' that can be simplified to a single 'notIn' condition.");

            results.Should().ContainEquivalentOf(typeFinding);
            results.Should().ContainEquivalentOf(locationFinding);
        }

        [Fact]
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_AnyOf_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
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
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""type"",
                            ""notEquals"": ""Microsoft.Storage/storageAccounts""
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
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_ExpressionFieldValue_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
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
                            ""field"": ""[parameters('fieldName')]"",
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""[parameters('fieldName')]"",
                            ""notEquals"": ""Microsoft.Storage/storageAccounts""
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
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_MixedOperatorSameField_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
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
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
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
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_SameValueRepeated_Violation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
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
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""type"",
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
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
                RuleIdentifier: "simplify-multiple-notequals-to-notin",
                Title: "Simplify Multiple NotEquals to NotIn",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.allOf[0]",
                Description: "The 'allOf' contains 2 'notEquals' conditions on field 'type' that can be simplified to a single 'notIn' condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_SimplifyMultipleNotEqualsToNotIn_CaseInsensitiveFieldMatching_Violation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new SimplifyMultipleNotEqualsToNotIn()
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
                            ""field"": ""Type"",
                            ""notEquals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""field"": ""type"",
                            ""notEquals"": ""Microsoft.Storage/storageAccounts""
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
                RuleIdentifier: "simplify-multiple-notequals-to-notin",
                Title: "Simplify Multiple NotEquals to NotIn",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.allOf[0]",
                Description: "The 'allOf' contains 2 'notEquals' conditions on field 'Type' that can be simplified to a single 'notIn' condition.");

            results.Should().ContainEquivalentOf(output);
        }
    }
}
