namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="FieldFunctionOnCountedArrayAlias"/> rule.
    /// </summary>
    public class FieldFunctionOnCountedArrayAliasTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_FieldFunctionOnCountedArrayAlias_Equals()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""value"": ""[field('Microsoft.Test/widgets/items[*]')]"",
                            ""equals"": ""approved""
                          }
                        },
                        ""greater"": 0
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
                RuleIdentifier: "field-function-on-counted-array-alias",
                Title: "Field Function on Counted Array Alias",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 81,
                Path: "properties.policyRule.if.count.where.value",
                Description: "The field() function on the counted alias 'Microsoft.Test/widgets/items[*]' returns a one-member array inside count.where, while current('Microsoft.Test/widgets/items[*]') returns the current scalar value. Use current('Microsoft.Test/widgets/items[*]') for this scalar comparison.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_FieldFunctionOnCountedArrayAlias_FieldFunctionAsOperatorValue()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""field"": ""Microsoft.Test/widgets/items[*].name"",
                            ""equals"": ""[field('Microsoft.Test/widgets/items[*].name')]""
                          }
                        },
                        ""greater"": 0
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
                RuleIdentifier: "field-function-on-counted-array-alias",
                Title: "Field Function on Counted Array Alias",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 10,
                LinePosition: 87,
                Path: "properties.policyRule.if.count.where.equals",
                Description: "The field() function on the counted alias 'Microsoft.Test/widgets/items[*].name' returns a one-member array inside count.where, while current('Microsoft.Test/widgets/items[*].name') returns the current scalar value. Use current('Microsoft.Test/widgets/items[*].name') for this scalar comparison.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_FieldFunctionOnCountedArrayAlias_MatchOperatorOnChildAlias()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""value"": ""[field('Microsoft.Test/widgets/items[*].name')]"",
                            ""match"": ""approved""
                          }
                        },
                        ""greater"": 0
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
                RuleIdentifier: "field-function-on-counted-array-alias",
                Title: "Field Function on Counted Array Alias",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 86,
                Path: "properties.policyRule.if.count.where.value",
                Description: "The field() function on the counted alias 'Microsoft.Test/widgets/items[*].name' returns a one-member array inside count.where, while current('Microsoft.Test/widgets/items[*].name') returns the current scalar value. Use current('Microsoft.Test/widgets/items[*].name') for this scalar comparison.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_FieldFunctionOnCountedArrayAlias_OrderingOperator()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""value"": ""[field('Microsoft.Test/widgets/items[*].priority')]"",
                            ""greaterOrEquals"": 1
                          }
                        },
                        ""greater"": 0
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
                RuleIdentifier: "field-function-on-counted-array-alias",
                Title: "Field Function on Counted Array Alias",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 90,
                Path: "properties.policyRule.if.count.where.value",
                Description: "The field() function on the counted alias 'Microsoft.Test/widgets/items[*].priority' returns a one-member array inside count.where, while current('Microsoft.Test/widgets/items[*].priority') returns the current scalar value. Use current('Microsoft.Test/widgets/items[*].priority') for this scalar comparison.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_FieldFunctionOnCountedArrayAlias_MixedCasing()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""value"": ""[field('mIcRoSoFt.TeSt/WiDgEtS/ItEmS[*].name')]"",
                            ""equals"": ""approved""
                          }
                        },
                        ""greater"": 0
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
                RuleIdentifier: "field-function-on-counted-array-alias",
                Title: "Field Function on Counted Array Alias",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 86,
                Path: "properties.policyRule.if.count.where.value",
                Description: "The field() function on the counted alias 'mIcRoSoFt.TeSt/WiDgEtS/ItEmS[*].name' returns a one-member array inside count.where, while current('mIcRoSoFt.TeSt/WiDgEtS/ItEmS[*].name') returns the current scalar value. Use current('mIcRoSoFt.TeSt/WiDgEtS/ItEmS[*].name') for this scalar comparison.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_FieldFunctionOnCountedArrayAlias_NestedCountUsesMatchingScope()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""count"": {
                              ""field"": ""Microsoft.Test/widgets/items[*].children[*]"",
                              ""where"": {
                                ""value"": ""[field('Microsoft.Test/widgets/items[*].children[*].name')]"",
                                ""less"": ""m""
                              }
                            },
                            ""greater"": 0
                          }
                        },
                        ""greater"": 0
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
                RuleIdentifier: "field-function-on-counted-array-alias",
                Title: "Field Function on Counted Array Alias",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: 102,
                Path: "properties.policyRule.if.count.where.count.where.value",
                Description: "The field() function on the counted alias 'Microsoft.Test/widgets/items[*].children[*].name' returns a one-member array inside count.where, while current('Microsoft.Test/widgets/items[*].children[*].name') returns the current scalar value. Use current('Microsoft.Test/widgets/items[*].children[*].name') for this scalar comparison.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("[current('Microsoft.Test/widgets/items[*].name')]")]
        [InlineData("[first(field('Microsoft.Test/widgets/items[*].name'))]")]
        [InlineData("[length(field('Microsoft.Test/widgets/items[*].name'))]")]
        public void RuleTests_FieldFunctionOnCountedArrayAlias_OtherRootFunction_NoFinding(string value)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""value"": ""__VALUE__"",
                            ""equals"": ""approved""
                          }
                        },
                        ""greater"": 0
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            policyDefinition = policyDefinition.Replace("__VALUE__", value);
            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldFunctionOnCountedArrayAlias_FieldOutsideCount_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[field('Microsoft.Test/widgets/items[*].name')]"",
                        ""equals"": ""approved""
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
        public void RuleTests_FieldFunctionOnCountedArrayAlias_DifferentArrayInsideCount_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""value"": ""[field('Microsoft.Test/widgets/otherItems[*].name')]"",
                            ""equals"": ""approved""
                          }
                        },
                        ""greater"": 0
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
        [InlineData("contains", "\"approved\"")]
        [InlineData("in", "[\"approved\"]")]
        [InlineData("exists", "true")]
        public void RuleTests_FieldFunctionOnCountedArrayAlias_ExcludedOperator_NoFinding(string operatorName, string operatorValue)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""value"": ""[field('Microsoft.Test/widgets/items[*].name')]"",
                            ""__OPERATOR__"": __OPERAND__
                          }
                        },
                        ""greater"": 0
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            policyDefinition = policyDefinition
                .Replace("__OPERATOR__", operatorName)
                .Replace("__OPERAND__", operatorValue);
            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldFunctionOnCountedArrayAlias_UnresolvedDynamicFieldArgument_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""parameters"": {
                      ""alias"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""value"": ""[field(parameters('alias'))]"",
                            ""equals"": ""approved""
                          }
                        },
                        ""greater"": 0
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
        public void RuleTests_FieldFunctionOnCountedArrayAlias_ValueContainsExpressionAndOtherText_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldFunctionOnCountedArrayAlias()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""count"": {
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
                          ""where"": {
                            ""value"": [
                              ""[field('Microsoft.Test/widgets/items[*].name')]"",
                              ""other text""
                            ],
                            ""equals"": ""approved""
                          }
                        },
                        ""greater"": 0
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
