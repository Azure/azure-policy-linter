namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="PolicyRuleReferencesMultipleResourceTypes"/> rule.
    /// </summary>
    public class PolicyRuleReferencesMultipleResourceTypesTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_SingleResourceType()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_InOperator_SingleResourceType()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_InOperator_MultipleResourceTypes()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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
            results[0].RuleIdentifier.Should().Be("policy-rule-references-multiple-resource-types");
            results[0].Severity.Should().Be(Severity.Informational);
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_InOperator_SameResourceTypeMultipleTimes()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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

            // Same resource type multiple times should not fire (HashSet deduplicates).
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_NotInOperator_MultipleResourceTypes_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_InOperator_WithNonResourceTypeValues()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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
                          """",
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

            // Should still detect multiple resource types, ignoring invalid and empty values.
            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-references-multiple-resource-types");
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_MultipleResourceTypes()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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
                RuleIdentifier: "policy-rule-references-multiple-resource-types",
                Title: "Policy Rule References Multiple Resource Types",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: "The policy rule references multiple resource types: Microsoft.Storage/storageAccounts, Microsoft.Compute/virtualMachines. Targeting several related types is a valid pattern; if this is unintended, target a single type and group policies with an initiative.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_NestedAllOf()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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
            results[0].RuleIdentifier.Should().Be("policy-rule-references-multiple-resource-types");
            results[0].Severity.Should().Be(Severity.Informational);
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_WithNotCondition()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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
            results[0].RuleIdentifier.Should().Be("policy-rule-references-multiple-resource-types");
            results[0].Severity.Should().Be(Severity.Informational);
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_DuplicateResourceType()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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

            // Same resource type multiple times should not fire.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_NoFieldConditions()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_NonTypeFieldReferences()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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

            // Non-type field references should not fire.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_MixedFieldTypes()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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

            // Single resource type with other field conditions is fine.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_CountExpression()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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

            // Single resource type with count expressions on its properties is fine.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_CountExpressionMultipleResourceTypes()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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

            // Fires because the if references both Microsoft.Storage/storageAccounts and Microsoft.Compute/virtualMachines via the type field.
            results.Should().HaveCount(1);
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_NotWrapper_InOperator_SingleNot_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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

            // Single ""not"" wrapper (odd count) negates the ""in"" - this acts like ""notIn"".
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_NotWrapper_InOperator_DoubleNot_ShouldFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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

            // Double ""not"" wrapper (even count = 2) processes the ""in"" - negatives cancel out.
            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-references-multiple-resource-types");
            results[0].Severity.Should().Be(Severity.Informational);
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_NotWrapper_InOperator_ZeroNot_ShouldFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
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

            // Zero ""not"" wrappers (even count = 0) processes the ""in"".
            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("policy-rule-references-multiple-resource-types");
            results[0].Severity.Should().Be(Severity.Informational);
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_InOperator_ParameterizedValue_ShouldNotThrow()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""parameters"": {
                      ""types"": { ""type"": ""Array"" }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""in"": ""[parameters('types')]""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // A parameterized ""in"" operand is not a literal array, so there is nothing to extract and no finding.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_EqualsOperator_ParameterizedValue_ShouldNotThrow()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""parameters"": {
                      ""resourceType"": { ""type"": ""String"" }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""[parameters('resourceType')]""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // A parameterized ""equals"" operand is not a literal resource type, so there is nothing to extract and no finding.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_PolicyRuleReferencesMultipleResourceTypes_BroadOperatorOnType_NamesNoConcreteType_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new PolicyRuleReferencesMultipleResourceTypes()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""contains"": ""virtualMachines""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // A broad operator (contains/like/match) names no concrete resource type, so there is
            // nothing for this rule to count and it does not fire.
            results.Should().BeEmpty();
        }
    }
}
