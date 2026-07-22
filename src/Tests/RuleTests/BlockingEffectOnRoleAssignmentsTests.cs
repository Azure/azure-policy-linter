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

        /// <summary>
        /// Builds the full expected finding anchored at the 'then.effect' property.
        /// </summary>
        private static LinterOutput ExpectedWarning(int lineNumber, int linePosition, string effect = "deny")
        {
            return new LinterOutput(
                RuleIdentifier: "blocking-effect-on-role-assignments",
                Title: "Blocking Effect on Role Assignments",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: lineNumber,
                LinePosition: linePosition,
                Path: "properties.policyRule.then.effect",
                Description: $"The '{effect}' effect blocks role assignment creation or PIM activation, which can lock administrators out of the policy scope. Ensure a standing recovery path at a parent scope that does not require creating a new role assignment.");
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 11, linePosition: 40));
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_DenyEqualsRoleAssignmentScheduleRequests()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Authorization/roleAssignmentScheduleRequests""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 11, linePosition: 40));
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_InSetContainingRoleAssignmentScheduleRequests()
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
                          ""Microsoft.Authorization/roleAssignmentScheduleRequests""
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 14, linePosition: 40));
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 11, linePosition: 40));
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 14, linePosition: 40));
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 19, linePosition: 40));
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
        public void RuleTests_BlockingEffectOnRoleAssignments_NotEqualsTypeCondition_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""notEquals"": ""Microsoft.Authorization/roleAssignments""
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
        public void RuleTests_BlockingEffectOnRoleAssignments_NotAroundNotEquals_Fires()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""field"": ""type"",
                          ""notEquals"": ""Microsoft.Authorization/roleAssignments""
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 13, linePosition: 40));
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_NotLikeTypeCondition_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""notLike"": ""Microsoft.Authorization/*""
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
        public void RuleTests_BlockingEffectOnRoleAssignments_NotInTypeCondition_ShouldNotFire()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""notIn"": [ ""Microsoft.Authorization/roleAssignments"" ]
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
        public void RuleTests_BlockingEffectOnRoleAssignments_NonSimpleEffectExpression_ShouldNotFire()
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
                        ""effect"": ""[concat('de', 'ny')]""
                      }
                    }
                  }
                }";

            var results = BlockingEffectOnRoleAssignmentsTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 18, linePosition: 58));
        }

        [Fact]
        public void RuleTests_BlockingEffectOnRoleAssignments_ParameterizedEffectNoAllowedValues_Fires()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 17, linePosition: 58));
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 11, linePosition: 40));
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 11, linePosition: 40));
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 15, linePosition: 40));
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
            results.Should().ContainEquivalentOf(
                BlockingEffectOnRoleAssignmentsTests.ExpectedWarning(lineNumber: 11, linePosition: 40, effect: "Deny"));
        }
    }
}
