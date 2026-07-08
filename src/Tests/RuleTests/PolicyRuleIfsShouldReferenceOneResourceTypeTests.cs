namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="PolicyRuleIfsShouldReferenceOneResourceType"/> rule.
    /// </summary>
    public class PolicyRuleIfsShouldReferenceOneResourceTypeTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_SingleResourceType()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_InOperator_SingleResourceType()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_InOperator_MultipleResourceTypes()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_InOperator_SameResourceTypeMultipleTimes()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_NotInOperator_MultipleResourceTypes_ShouldNotWarn()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_InOperator_WithNonResourceTypeValues()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_MultipleResourceTypes()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_NestedAllOf()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_WithNotCondition()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_DuplicateResourceType()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_NoFieldConditions()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_NonTypeFieldReferences()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_MixedFieldTypes()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_CountExpression()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_CountExpressionMultipleResourceTypes()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_ContainsOperator_ShouldWarn()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_LikeOperator_ShouldWarn()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_MatchOperator_ShouldWarn()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_MatchInsensitivelyOperator_ShouldWarn()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_WildcardOperatorWithExplicitResourceType_ShouldWarn()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_WildcardOperatorOnNonTypeField_ShouldNotWarn()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_MultipleWildcardOperators_ShouldWarn()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_NotWrapper_InOperator_SingleNot_ShouldNotWarn()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_NotWrapper_InOperator_DoubleNot_ShouldWarn()
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
        void LinterTests_PolicyRuleIfsShouldReferenceOneResourceType_NotWrapper_InOperator_ZeroNot_ShouldWarn()
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
