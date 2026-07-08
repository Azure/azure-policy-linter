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
    /// Test the implementation of common linter rules.
    /// </summary>
    public class CommonRuleTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        void LinterTests_CommonRules_TypeConditionFirstInAllOf_TypeIsFirst()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new TypeConditionFirstInAllOf()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
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
        void LinterTests_CommonRules_TypeConditionFirstInAllOf_TypeIsNotFirst()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new TypeConditionFirstInAllOf()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""location"",
                            ""equals"": ""eastus""
                          },
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
                RuleIdentifier: "type-condition-first-in-allof",
                Title: "Type condition should be first in allOf",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: 27,
                Path: "properties.policyRule.if.allOf[1]",
                Description: "The type condition at index 1 should be moved to the first position in the allOf for readability, so that readers immediately see which resource type the policy targets.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_TypeConditionFirstInAllOf_TypeAtIndexTwo()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new TypeConditionFirstInAllOf()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""location"",
                            ""equals"": ""eastus""
                          },
                          {
                            ""field"": ""tags['environment']"",
                            ""exists"": true
                          },
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
                RuleIdentifier: "type-condition-first-in-allof",
                Title: "Type condition should be first in allOf",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 27,
                Path: "properties.policyRule.if.allOf[2]",
                Description: "The type condition at index 2 should be moved to the first position in the allOf for readability, so that readers immediately see which resource type the policy targets.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_TypeConditionFirstInAllOf_NoTypeCondition()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new TypeConditionFirstInAllOf()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""location"",
                            ""equals"": ""eastus""
                          },
                          {
                            ""field"": ""tags['environment']"",
                            ""exists"": true
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
        void LinterTests_CommonRules_TypeConditionFirstInAllOf_SingleConditionAllOf()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new TypeConditionFirstInAllOf()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
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

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_TypeConditionFirstInAllOf_AnyOfNotChecked()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new TypeConditionFirstInAllOf()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""anyOf"": [
                          {
                            ""field"": ""location"",
                            ""equals"": ""eastus""
                          },
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

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_TypeConditionFirstInAllOf_CaseInsensitive()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new TypeConditionFirstInAllOf()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""Type"",
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
        void LinterTests_CommonRules_SimplifyMultipleEqualsToIn_Violation()
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
                Title: "Simplify multiple equals to in",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.anyOf[0]",
                Description: "The anyOf contains 2 equals conditions on field \"type\" that can be simplified to a single \"in\" condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_SimplifyMultipleEqualsToIn_DifferentFields_NoViolation()
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
        void LinterTests_CommonRules_SimplifyMultipleEqualsToIn_SingleEquals_NoViolation()
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
        void LinterTests_CommonRules_SimplifyMultipleEqualsToIn_AlreadyUsesIn_NoViolation()
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
        void LinterTests_CommonRules_SimplifyMultipleEqualsToIn_ThreeEqualsOnSameField()
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
                Title: "Simplify multiple equals to in",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.anyOf[0]",
                Description: "The anyOf contains 3 equals conditions on field \"type\" that can be simplified to a single \"in\" condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_SimplifyMultipleEqualsToIn_MultipleFieldGroups()
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
        }

        [Fact]
        void LinterTests_CommonRules_SimplifyMultipleEqualsToIn_AllOf_NoViolation()
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
        void LinterTests_CommonRules_SimplifyMultipleEqualsToIn_CaseInsensitiveFieldMatching()
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
        }

        [Fact]
        void LinterTests_CommonRules_SimplifyMultipleNotEqualsToNotIn_Violation()
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
                Title: "Simplify multiple notEquals to notIn",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.allOf[0]",
                Description: "The allOf contains 2 notEquals conditions on field \"type\" that can be simplified to a single \"notIn\" condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_SimplifyMultipleNotEqualsToNotIn_DifferentFields_NoViolation()
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
        void LinterTests_CommonRules_SimplifyMultipleNotEqualsToNotIn_SingleNotEquals_NoViolation()
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
        void LinterTests_CommonRules_SimplifyMultipleNotEqualsToNotIn_AlreadyUsesNotIn_NoViolation()
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
        void LinterTests_CommonRules_SimplifyMultipleNotEqualsToNotIn_ThreeNotEqualsOnSameField()
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
                Title: "Simplify multiple notEquals to notIn",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 27,
                Path: "properties.policyRule.if.allOf[0]",
                Description: "The allOf contains 3 notEquals conditions on field \"type\" that can be simplified to a single \"notIn\" condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_SimplifyMultipleNotEqualsToNotIn_MultipleFieldGroups()
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
        }

        [Fact]
        void LinterTests_CommonRules_SimplifyMultipleNotEqualsToNotIn_AnyOf_NoViolation()
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
        void LinterTests_CommonRules_SimplifyMultipleNotEqualsToNotIn_CaseInsensitiveFieldMatching()
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
        }


        [Fact]
        void LinterTests_CommonRules_EffectParameterShouldHaveAllowedAndDefaultValues_BothMissing()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(2);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' is missing 'allowedValues'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' is missing 'defaultValue'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));
        }

        [Fact]
        void LinterTests_CommonRules_EffectParameterShouldHaveAllowedAndDefaultValues_AllowedValuesMissing()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 17,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' is missing 'allowedValues'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));
        }

        [Fact]
        void LinterTests_CommonRules_EffectParameterShouldHaveAllowedAndDefaultValues_DefaultValueMissing()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 21,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' is missing 'defaultValue'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));
        }

        [Fact]
        void LinterTests_CommonRules_EffectParameterShouldHaveAllowedAndDefaultValues_BothPresent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectParameterShouldHaveAllowedAndDefaultValues_HardCodedEffect()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
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
        void LinterTests_CommonRules_EffectParameterShouldHaveAllowedAndDefaultValues_CustomParameterName()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""policyEffect"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('policyEffect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(2);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 64,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'policyEffect' is missing 'allowedValues'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 64,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'policyEffect' is missing 'defaultValue'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_ValidSameCategory()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_MixNoDetailsAndModify()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Modify"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_MixNoDetailsAndIfNotExists()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""AuditIfNotExists"",
                        ""allowedValues"": [
                          ""Deny"",
                          ""AuditIfNotExists"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_MixAllThreeCategories()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Modify"",
                          ""DeployIfNotExists"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-allowed-values-should-not-mix-incompatible-effects",
                Title: "Effect Allowed Values Should Not Mix Incompatible Effects",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 23,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect': allowedValues mixes effects from incompatible effects: IfNotExistsDetails (DeployIfNotExists), ModifyDetails (Modify). Effects in each category require a different 'details' block configuration and cannot coexist in the same allowedValues."));
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_IfNotExistsCategoryOnly()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""AuditIfNotExists"",
                        ""allowedValues"": [
                          ""AuditIfNotExists"",
                          ""DeployIfNotExists"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_CaseInsensitive()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""audit"",
                        ""allowedValues"": [
                          ""audit"",
                          ""modify"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_NotParameterized()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
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
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_NoAllowedValues()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_OnlyUncategorizedEffects()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_CustomParameterName()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""policyEffect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Modify"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('policyEffect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_CategorizedWithUncategorized()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Append"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_MultipleValuesPerCategory()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Modify"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_EmptyAllowedValues()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": []
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_ExplicitlyNullAllowedValues()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": null
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_DataplaneModeSkipped()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Microsoft.Kubernetes.Data"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Modify"",
                          ""DeployIfNotExists"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.ContainerService/managedClusters""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_EffectAllowedValuesShouldNotMixIncompatibleEffects_UnknownEffectNoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""FutureEffect"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_MatchWithoutWildcards_MatchWithoutWildcards_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""match"": ""my-resource-name""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // match is case-sensitive with no case-insensitive equivalent, so no suggestion
            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_MatchWithoutWildcards_NotMatchWithoutWildcards_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""notMatch"": ""my-resource-name""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // notMatch is case-sensitive with no case-insensitive equivalent, so no suggestion
            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_MatchWithoutWildcards_MatchInsensitivelyWithoutPlaceholders()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""matchInsensitively"": ""my-resource-name""
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
                RuleIdentifier: "match-without-wildcards",
                Title: "match/matchInsensitively Without Wildcards",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 64,
                Path: "properties.policyRule.if.matchInsensitively",
                Description: "The condition uses the 'matchInsensitively' operator with value 'my-resource-name' which contains no wildcards (#, ?, or .). Use 'equals' instead to better reflect the intention of exact matching.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_MatchWithoutWildcards_NotMatchInsensitivelyWithoutPlaceholders()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""notMatchInsensitively"": ""my-resource-name""
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
                RuleIdentifier: "match-without-wildcards",
                Title: "match/matchInsensitively Without Wildcards",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 67,
                Path: "properties.policyRule.if.notMatchInsensitively",
                Description: "The condition uses the 'notMatchInsensitively' operator with value 'my-resource-name' which contains no wildcards (#, ?, or .). Use 'notEquals' instead to better reflect the intention of exact matching.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("match", "my-resource-##")]
        [InlineData("match", "my-resource-?ame")]
        [InlineData("match", "my-resource-.ame")]
        [InlineData("matchInsensitively", "resource-##")]
        [InlineData("notMatch", "resource-?ame")]
        [InlineData("notMatchInsensitively", "resource-.")]
        void LinterTests_CommonRules_MatchWithoutWildcards_WithPlaceholders_NoViolation(string operatorName, string operandValue)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""name"",
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
        void LinterTests_CommonRules_MatchWithoutWildcards_ParameterizedValue_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
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
                        ""field"": ""name"",
                        ""match"": ""[parameters('pattern')]""
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
        [InlineData("like")]
        [InlineData("contains")]
        void LinterTests_CommonRules_MatchWithoutWildcards_OtherOperators_NoViolation(string operatorName)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""name"",
                        ""{operatorName}"": ""my-resource-name""
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
        void LinterTests_CommonRules_NestedSameTypeQuantifiersShouldBeFlattened_AllOfInsideAllOf()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
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
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""allOf"": [
                              {
                                ""field"": ""location"",
                                ""equals"": ""eastus""
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "nested-same-type-quantifiers-should-be-flattened",
                Title: "Nested same-type quantifiers should be flattened",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 38,
                Path: "properties.policyRule.if.allOf[1].allOf",
                Description: "This \"allOf\" quantifier is nested inside a parent \"allOf\" and can be flattened into it.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_NestedSameTypeQuantifiersShouldBeFlattened_AnyOfInsideAnyOf()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedSameTypeQuantifiersShouldBeFlattened()
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
                            ""anyOf"": [
                              {
                                ""field"": ""location"",
                                ""equals"": ""eastus""
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "nested-same-type-quantifiers-should-be-flattened",
                Title: "Nested same-type quantifiers should be flattened",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 38,
                Path: "properties.policyRule.if.anyOf[1].anyOf",
                Description: "This \"anyOf\" quantifier is nested inside a parent \"anyOf\" and can be flattened into it.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_NestedSameTypeQuantifiersShouldBeFlattened_AllOfInsideAnyOf_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedSameTypeQuantifiersShouldBeFlattened()
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
                            ""allOf"": [
                              {
                                ""field"": ""location"",
                                ""equals"": ""eastus""
                              },
                              {
                                ""field"": ""tags.env"",
                                ""equals"": ""prod""
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
        void LinterTests_CommonRules_NestedSameTypeQuantifiersShouldBeFlattened_NoNestedQuantifier_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
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
        void LinterTests_CommonRules_NestedSameTypeQuantifiersShouldBeFlattened_MultipleNestedAllOf()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
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
                          },
                          {
                            ""field"": ""location"",
                            ""equals"": ""eastus""
                          },
                          {
                            ""allOf"": [
                              {
                                ""field"": ""tags.env"",
                                ""equals"": ""prod""
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

            var output0 = new LinterOutput(
                RuleIdentifier: "nested-same-type-quantifiers-should-be-flattened",
                Title: "Nested same-type quantifiers should be flattened",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 38,
                Path: "properties.policyRule.if.allOf[0].allOf",
                Description: "This \"allOf\" quantifier is nested inside a parent \"allOf\" and can be flattened into it.");

            var output2 = new LinterOutput(
                RuleIdentifier: "nested-same-type-quantifiers-should-be-flattened",
                Title: "Nested same-type quantifiers should be flattened",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 21,
                LinePosition: 38,
                Path: "properties.policyRule.if.allOf[2].allOf",
                Description: "This \"allOf\" quantifier is nested inside a parent \"allOf\" and can be flattened into it.");

            results.Should().ContainEquivalentOf(output0);
            results.Should().ContainEquivalentOf(output2);
        }

        [Fact]
        void LinterTests_CommonRules_NestedSameTypeQuantifiersShouldBeFlattened_NotQuantifier_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedSameTypeQuantifiersShouldBeFlattened()
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
        void LinterTests_CommonRules_NestedSameTypeQuantifiersShouldBeFlattened_NestedAtIndexZero()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedSameTypeQuantifiersShouldBeFlattened()
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
                            ""anyOf"": [
                              {
                                ""field"": ""type"",
                                ""equals"": ""Microsoft.Compute/virtualMachines""
                              }
                            ]
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "nested-same-type-quantifiers-should-be-flattened",
                Title: "Nested same-type quantifiers should be flattened",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 38,
                Path: "properties.policyRule.if.anyOf[0].anyOf",
                Description: "This \"anyOf\" quantifier is nested inside a parent \"anyOf\" and can be flattened into it.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_AllParameterReferencesMustResolve_UnresolvedParameter()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new AllParameterReferencesMustResolve()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('efect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "all-parameter-references-must-resolve",
                Title: "All Parameter References Must Resolve",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 17,
                LinePosition: 57,
                Path: "properties.policyRule.then.effect",
                Description: "Found a reference to parameter 'efect', but no matching parameter definition found. Check for typos or references to removed parameters.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_AllParameterReferencesMustResolve_AllParametersResolved()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new AllParameterReferencesMustResolve()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_AllParameterReferencesMustResolve_CaseInsensitiveMatch()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new AllParameterReferencesMustResolve()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('Effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_AllParameterReferencesMustResolve_MultipleUnresolvedParameters()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new AllParameterReferencesMustResolve()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""[parameters('fieldName')]"",
                        ""equals"": ""[parameters('expectedValue')]""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(2);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "all-parameter-references-must-resolve",
                Title: "All Parameter References Must Resolve",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 60,
                Path: "properties.policyRule.if.field",
                Description: "Found a reference to parameter 'fieldName', but no matching parameter definition found. Check for typos or references to removed parameters."));

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "all-parameter-references-must-resolve",
                Title: "All Parameter References Must Resolve",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 14,
                LinePosition: 65,
                Path: "properties.policyRule.if.equals",
                Description: "Found a reference to parameter 'expectedValue', but no matching parameter definition found. Check for typos or references to removed parameters."));
        }

        [Fact]
        void LinterTests_CommonRules_AllParameterReferencesMustResolve_NoParameters()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new AllParameterReferencesMustResolve()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_AllParameterReferencesMustResolve_NoParameterReferences()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new AllParameterReferencesMustResolve()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
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
        void LinterTests_CommonRules_AllParameterReferencesMustResolve_ParameterInComplexExpression()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new AllParameterReferencesMustResolve()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""tagName"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""[concat('tags[', parameters('tagNme'), ']')]"",
                        ""exists"": ""false""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "all-parameter-references-must-resolve",
                Title: "All Parameter References Must Resolve",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: 79,
                Path: "properties.policyRule.if.field",
                Description: "Found a reference to parameter 'tagNme', but no matching parameter definition found. Check for typos or references to removed parameters."));
        }


        [Fact]
        void LinterTests_CommonRules_FieldAliasUnavailableInOldApiVersions()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInOldApiVersions()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": { // L10
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""value"": ""[field('Microsoft.Storage/storageAccounts/networkAcls.defaultAction')]"",
                            ""equals"": ""Allow""
                          }, // L20
                          {
                            ""count"": {
                              ""field"": ""Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]"",
                              ""where"": {
                                ""allOf"": [
                                  {
                                    ""field"": ""Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].action"",
                                    ""notEquals"": ""deny""
                                  },
                                  { // L30
                                    ""count"": {
                                      ""value"": ""[parameters('approvedIpRanges')]"",
                                      ""name"": ""approvedIpRange"",
                                      ""where"": {
                                        ""value"": ""[ipRangeContains(current('approvedIpRange'), current('Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].value'))]"",
                                        ""equals"": true
                                      }
                                    },
                                    ""equals"": 0
                                  }
                                ]
                              }
                            },
                            ""greater"": 0
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

            results.Should().HaveCount(4);

            var output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 109,
                Path: "properties.policyRule.if.allOf[1].value",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.defaultAction' maps to property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);

            output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 23,
                LinePosition: 97,
                Path: "properties.policyRule.if.allOf[2].count.field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]' maps to property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);

            output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 27,
                LinePosition: 110,
                Path: "properties.policyRule.if.allOf[2].count.where.allOf[0].field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].action' maps to property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);

            output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 35,
                LinePosition: 171,
                Path: "properties.policyRule.if.allOf[2].count.where.allOf[1].count.where.value",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].value' maps to property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_FieldAliasUnavailableInLatestApiVersions()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInLatestApiVersion()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.DocumentDB/databaseAccounts""
                          },
                          {
                            ""field"": ""Microsoft.DocumentDB/databaseAccounts/ipRangeFilter"",
                            ""equals"": ""Allow""
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
                RuleIdentifier: "field-alias-unavailable-in-latest-api-version",
                Title: "Field Alias Unavailable In Latest API Version",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 90,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.DocumentDB/databaseAccounts/ipRangeFilter' is referring to a property that doesn't exist in the latest API version (2025-11-01-preview) of resource type: 'Microsoft.DocumentDB/databaseAccounts'. This most likely means that the referenced property is deprecated and the policy might not work as intended.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_ReadOnlyFieldAlias()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ReadOnlyFieldAlias()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/privateEndpointConnections"",
                            ""equals"": ""Something""
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
                RuleIdentifier: "read-only-field-alias",
                Title: "Read-Only Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 99,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/privateEndpointConnections' maps to property that is marked as read-only in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2019-06-01, 2020-08-01-preview, 2021-01-01, 2021-02-01, 2021-04-01, 2021-06-01, 2021-08-01, 2021-09-01, 2022-05-01, 2022-09-01, 2023-01-01, 2023-04-01, 2023-05-01, 2024-01-01, 2025-01-01, 2025-06-01, 2025-08-01, 2026-04-01'");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_OptionalOnlyFieldAlias()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"",
                            ""equals"": ""Something""
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
                RuleIdentifier: "optional-field-alias",
                Title: "Optional Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 94,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/allowBlobPublicAccess' maps to property path that marked as optional in some API version of resource type: 'Microsoft.Storage/storageAccounts' . API versions: '2019-04-01, 2019-06-01, 2020-08-01-preview, 2021-01-01, 2021-02-01, 2021-04-01, 2021-06-01, 2021-08-01, 2021-09-01, 2022-05-01, 2022-09-01, 2023-01-01, 2023-04-01, 2023-05-01, 2024-01-01, 2025-01-01, 2025-06-01, 2025-08-01, 2026-04-01'");
            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_ConditionalFieldAlias()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ConditionalFieldAlias()
                },
                metadata: TypeMetadata);

            // The "folderPath" property is only present in data factory triggers of type "BlobTrigger"
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.DataFactory/factories/triggers""
                          },
                          {
                            ""field"": ""Microsoft.DataFactory/factories/triggers/BlobTrigger.typeProperties.folderPath"",
                            ""equals"": ""Something""
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
                RuleIdentifier: "conditional-field-alias",
                Title: "Conditional Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 117,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.DataFactory/factories/triggers/BlobTrigger.typeProperties.folderPath' maps to property path that only exists in the target resource type: 'Microsoft.DataFactory/factories/triggers' if some conditions are met. In all other cases, the property might be missing. Affected API versions: '2017-09-01-preview, 2018-06-01'");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_HardCodedEnforcementPolicyEffect_EnforcementEffect()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new HardCodedEnforcementPolicyEffect()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"",
                            ""equals"": ""Something""
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
                RuleIdentifier: "hard-coded-policy-enforcement-effect",
                Title: "Hard-Coded Enforcement Policy Effect",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 24,
                LinePosition: 40,
                Path: "properties.policyRule.then.effect",
                Description: "The policy definition has a hard-coded enforcement effect: 'deny'. Consider adding an \"effect\" policy definition parameter with default value: 'audit' and allowed values: 'audit,deny,disabled' and replace the hard-coded effect with \"[parameters('effect')]\". Parameterizing the policy effect makes it easy reuse the policy as well as to follow safe deployment practices (start with audit, then enforce).");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("audit")]
        [InlineData("[parameters('whatever')]")]
        void LinterTests_CommonRules_HardCodedEnforcementPolicyEffect_ShouldNotBeTriggered(string effectValue)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new HardCodedEnforcementPolicyEffect()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"",
                            ""equals"": ""Something""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    } 
                  }
                }";

            // Replace the hard-coded effect with the provided value
            policyDefinition = policyDefinition.Replace("deny", effectValue);
            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_RiskyEffectParameterDefaultValue_ParameterizedEffectWithRiskyDefault()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                   new RiskyEffectParameterDefaultValue()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"  
               {  
                 ""properties"": {  
                   ""mode"": ""Indexed"",  
                   ""parameters"": {  
                     ""effect"": {  
                       ""type"": ""String"",  
                       ""defaultValue"": ""deny"",  
                       ""allowedValues"": [  
                         ""audit"",  
                         ""deny"",  
                         ""disabled""  
                       ]  
                     }  
                   },  
                   ""policyRule"": {  
                     ""if"": {  
                       ""field"": ""type"",  
                       ""equals"": ""Microsoft.Storage/storageAccounts""  
                     },  
                     ""then"": {  
                       ""effect"": ""[parameters('effect')]""  
                     }  
                   }  
                 }  
               }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 57,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the default value of the reference parameter: 'effect' is: 'deny'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to: 'audit' and: 'audit,deny,disabled' as the parameter allowed values."
            );

            results.Should().ContainEquivalentOf(output);

            // Now try to get fancy and have the parameter name as a static language expression. Should still work.
            linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                   new RiskyEffectParameterDefaultValue()
                },
                metadata: TypeMetadata);

            policyDefinition = policyDefinition.Replace("[parameters('effect')]", "[parameters(concat('e', 'ffect'))]");
            results = linter.Lint(policyDefinition);
            results.Should().HaveCount(1);

            output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 69,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the default value of the reference parameter: 'effect' is: 'deny'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to: 'audit' and: 'audit,deny,disabled' as the parameter allowed values."
            );

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_UnnecessaryQuantifierWrapper_AllOfSingleExpression()
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
                Title: "Unnecessary allOf/anyOf wrapper",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 34,
                Path: "properties.policyRule.if.allOf",
                Description: "The \"allOf\" contains a single expression and can be removed. Use the inner expression directly.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_UnnecessaryQuantifierWrapper_AnyOfSingleExpression()
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
                Title: "Unnecessary allOf/anyOf wrapper",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 34,
                Path: "properties.policyRule.if.anyOf",
                Description: "The \"anyOf\" contains a single expression and can be removed. Use the inner expression directly.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_UnnecessaryQuantifierWrapper_AllOfMultipleExpressions_NoViolation()
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
        void LinterTests_CommonRules_UnnecessaryQuantifierWrapper_AnyOfMultipleExpressions_NoViolation()
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
        void LinterTests_CommonRules_UnnecessaryQuantifierWrapper_NoQuantifier_NoViolation()
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
        void LinterTests_CommonRules_UnnecessaryQuantifierWrapper_NotQuantifier_NoViolation()
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
        void LinterTests_CommonRules_UnnecessaryQuantifierWrapper_EmptyAllOf_NoViolation()
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
        void LinterTests_CommonRules_LikeNotLikeWithoutWildcards_LikeWithoutWildcard()
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
        void LinterTests_CommonRules_LikeNotLikeWithoutWildcards_NotLikeWithoutWildcard()
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
        void LinterTests_CommonRules_LikeNotLikeWithoutWildcards_WithWildcards_NoViolation(string operatorName, string operandValue)
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
        void LinterTests_CommonRules_LikeNotLikeWithoutWildcards_ParameterizedValue_NoViolation()
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
        void LinterTests_CommonRules_LikeNotLikeWithoutWildcards_OtherOperators_NoViolation(string operatorName)
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

        /// <summary>
        /// Mock type metadata for PolicyRuleIfsShouldReferenceOneResourceType tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_SingleResourceType()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
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
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_InOperator_SingleResourceType()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_InOperator_MultipleResourceTypes()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""in"": [
                          ""Microsoft.Storage/storageAccounts"",
                          ""Microsoft.Compute/virtualMachines""
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
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_InOperator_SameResourceTypeMultipleTimes()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""in"": [
                          ""Microsoft.Storage/storageAccounts"",
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

            // Same resource type multiple times should not trigger warning (HashSet will deduplicate)
            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_NotInOperator_MultipleResourceTypes_ShouldNotWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""notIn"": [
                          ""Microsoft.Storage/storageAccounts"",
                          ""Microsoft.Network/virtualNetworks"",
                          ""Microsoft.Compute/virtualMachines""
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
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_InOperator_WithNonResourceTypeValues()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""in"": [
                          ""Microsoft.Storage/storageAccounts"",
                          ""someInvalidValue"",
                          ""Microsoft.Compute/virtualMachines""
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // Should still detect multiple resource types, ignoring invalid values
            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_MultipleResourceTypes()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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
                RuleIdentifier: "policy-rule-should-contain-one-resource-type",
                Title: "Policies should reference one resource type",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: "It is best practice for the policy rule to only reference one resource type, referenced resource types Microsoft.Storage/storageAccounts, Microsoft.Compute/virtualMachines.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_NestedAllOf()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_WithNotCondition()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""allOf"": [
                            {
                              ""field"": ""type"",
                              ""equals"": ""Microsoft.Storage/storageAccounts""
                            },
                            {
                              ""field"": ""type"",
                              ""equals"": ""Microsoft.Network/virtualNetworks""
                            }
                          ]
                        }
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_DuplicateResourceType()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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

            // Same resource type multiple times should not trigger warning
            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_NoFieldConditions()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[parameters('effect')]"",
                        ""equals"": ""deny""
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
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_NonTypeFieldReferences()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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
                            ""field"": ""location"",
                            ""equals"": ""eastus""
                          },
                          {
                            ""field"": ""tags.environment"",
                            ""equals"": ""production""
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

            // Non-type field references should not trigger warning - this is fine
            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_MixedFieldTypes()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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
                            ""field"": ""location"",
                            ""in"": [""eastus"", ""westus""]
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

            // Single resource type with other field conditions is fine
            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_CountExpression()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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
                            ""count"": {
                              ""field"": ""Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]"",
                              ""where"": {
                                ""field"": ""Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].value"",
                                ""equals"": ""10.0.0.1""
                              }
                            },
                            ""greater"": 0
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

            // Single resource type with count expressions on its properties is fine
            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_CountExpressionMultipleResourceTypes()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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
                            ""equals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""count"": {
                              ""field"": ""Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]"",
                              ""where"": {
                                ""field"": ""Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].value"",
                                ""equals"": ""10.0.0.1""
                              }
                            },
                            ""greater"": 0
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

            // This should trigger a warning because it references both Microsoft.Storage/storageAccounts and Microsoft.Compute/virtualMachines via type field
            results.Should().HaveCount(1);
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_ContainsOperator_ShouldWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
            results[0].Description.Should().Contain("The policy uses wildcard operators when checking resource types");
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_LikeOperator_ShouldWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": ""Microsoft.Storage/*"",
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
            results[0].Description.Should().Contain("The policy uses wildcard operators when checking resource types");
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_MatchOperator_ShouldWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""match"": ""Microsoft.*"",
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
            results[0].Description.Should().Contain("The policy uses wildcard operators when checking resource types");
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_MatchInsensitivelyOperator_ShouldWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""matchInsensitively"": ""microsoft\\.storage/.*"",
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
            results[0].Description.Should().Contain("The policy uses wildcard operators when checking resource types");
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_WildcardOperatorWithExplicitResourceType_ShouldWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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
                            ""like"": ""Microsoft.Compute/*"",
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
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
            results[0].Description.Should().Contain("The policy uses wildcard operators when checking resource types");
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_WildcardOperatorOnNonTypeField_ShouldNotWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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
                            ""like"": ""prod-*"",
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

            // Should not warn - wildcard is on 'name' field, not 'type' field
            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_MultipleWildcardOperators_ShouldWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
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
                            ""contains"": ""Storage"",
                          },
                          {
                            ""field"": ""type"",
                            ""match"": ""Microsoft\\.Compute/.*"",
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

            // Multiple wildcard operators should still result in a single warning
            // because they all add the same warning string to the HashSet
            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_NotWrapper_InOperator_SingleNot_ShouldNotWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""field"": ""type"",
                          ""in"": [
                            ""Microsoft.Storage/storageAccounts"",
                            ""Microsoft.Compute/virtualMachines""
                          ]
                        }
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // Single "not" wrapper (odd count) should not process "in" - this acts like "notIn"
            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_NotWrapper_InOperator_DoubleNot_ShouldWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""not"": {
                            ""field"": ""type"",
                            ""in"": [
                              ""Microsoft.Storage/storageAccounts"",
                              ""Microsoft.Compute/virtualMachines""
                            ]
                          }
                        }
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // Double "not" wrapper (even count = 2) should process "in" - negatives cancel out
            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        void LinterTests_CommonRules_PolicyRuleIfsShouldReferenceOneResourceType_NotWrapper_InOperator_ZeroNot_ShouldWarn()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleIfsShouldReferenceOneResourceType()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""in"": [
                          ""Microsoft.Storage/storageAccounts"",
                          ""Microsoft.Compute/virtualMachines""
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // Zero "not" wrappers (even count = 0) should process "in"
            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-should-contain-one-resource-type");
            results[0].Severity.Should().Be(Severity.Warning);
        }
    }
}
