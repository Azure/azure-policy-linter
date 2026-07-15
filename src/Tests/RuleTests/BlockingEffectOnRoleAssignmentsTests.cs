namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="BlockingEffectOnRoleAssignments"/> rule.
    /// </summary>
    public class BlockingEffectOnRoleAssignmentsTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        private static PolicyLinter CreateLinter()
        {
            return new PolicyLinter(
                rules: new ILinterRule[] { new BlockingEffectOnRoleAssignments() },
                metadata: BlockingEffectOnRoleAssignmentsTests.MockMetadata);
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_DenyEqualsRoleAssignments()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Authorization/roleAssignments""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "blocking-effect-on-role-assignments",
                Title: "Blocking Effect on Role Assignments",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 11,
                LinePosition: 40,
                Path: "properties.policyRule.then.effect",
                Description: "The 'deny' effect blocks creation of role assignments ('Microsoft.Authorization/roleAssignments'), which can prevent just-in-time role activation and lock administrators out. Ensure a standing recovery path at a parent scope that does not rely on creating a new role assignment.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_DenyActionEqualsRoleAssignments_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Authorization/roleAssignments""
                      },
                      ""then"": {
                        ""effect"": ""denyAction""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_WildcardLikeNamespace()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": ""Microsoft.Authorization/*""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("blocking-effect-on-role-assignments");
            results[0].Severity.Should().Be(Severity.Warning);
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_InSetContainingRoleAssignments()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""in"": [
                          ""Microsoft.Compute/virtualMachines"",
                          ""Microsoft.Authorization/roleAssignments""
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("blocking-effect-on-role-assignments");
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_NestedTypeCondition()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""name"",
                            ""like"": ""prod-*""
                          },
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Authorization/roleAssignments""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("blocking-effect-on-role-assignments");
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_NonBlockingEffect_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Authorization/roleAssignments""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_DenyOnDifferentType_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
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

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_DenyWithoutTypeCondition_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""example""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_NegatedTypeCondition_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""field"": ""type"",
                          ""equals"": ""Microsoft.Authorization/roleAssignments""
                        }
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_ParameterizedEffectDefaultsToBlocking_Fires()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""deny""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Authorization/roleAssignments""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("blocking-effect-on-role-assignments");
            results[0].Description.Should().StartWith("The 'deny' effect blocks creation of role assignments");
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_ParameterizedEffectAllowsBlocking_Fires()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""allowedValues"": [ ""audit"", ""deny"" ],
                        ""defaultValue"": ""audit""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Authorization/roleAssignments""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("blocking-effect-on-role-assignments");
            results[0].Description.Should().StartWith("The 'deny' effect blocks creation of role assignments");
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_ParameterizedEffectNoBlockingValue_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""allowedValues"": [ ""audit"", ""disabled"" ],
                        ""defaultValue"": ""audit""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Authorization/roleAssignments""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_LikeSuffixWildcard()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": ""*/roleAssignments""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("blocking-effect-on-role-assignments");
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_LikeWithoutWildcard()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": ""Microsoft.Authorization/roleAssignments""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("blocking-effect-on-role-assignments");
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_LikeDifferentNamespace_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": ""Microsoft.Compute/*""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_ContainsOperator_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""contains"": ""Microsoft.Authorization/roleAssignments""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_DoubleNegatedTypeCondition_Fires()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""not"": {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Authorization/roleAssignments""
                          }
                        }
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("blocking-effect-on-role-assignments");
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_EmptyLikeValue_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": """"
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_CaseInsensitiveMatch()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""microsoft.authorization/ROLEASSIGNMENTS""
                      },
                      ""then"": {
                        ""effect"": ""Deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results[0].RuleIdentifier.Should().Be("blocking-effect-on-role-assignments");
        }
    }
}
