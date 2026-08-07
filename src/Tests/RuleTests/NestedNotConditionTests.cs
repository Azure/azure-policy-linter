// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="NestedNotCondition"/> rule.
    /// </summary>
    public class NestedNotConditionTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_NestedNotCondition_SimpleDoubleNot()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedNotCondition()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""not"": {
                            ""field"": ""location"",
                            ""equals"": ""eastus""
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "nested-not-condition",
                Title: "Nested Not Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 34,
                Path: "properties.policyRule.if.not.not",
                Description: "Two nested 'not' operators negate the same condition, which adds nesting without changing the result. Remove both.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_NestedNotCondition_DoubleNotUnderAllOf()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedNotCondition()
                },
                metadata: MockMetadata);

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
                            ""not"": {
                              ""not"": {
                                ""field"": ""location"",
                                ""equals"": ""eastus""
                              }
                            }
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
                RuleIdentifier: "nested-not-condition",
                Title: "Nested Not Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 14,
                LinePosition: 38,
                Path: "properties.policyRule.if.allOf[1].not.not",
                Description: "Two nested 'not' operators negate the same condition, which adds nesting without changing the result. Remove both.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_NestedNotCondition_DoubleNotUnderAnyOf()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedNotCondition()
                },
                metadata: MockMetadata);

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
                            ""not"": {
                              ""not"": {
                                ""field"": ""location"",
                                ""equals"": ""eastus""
                              }
                            }
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
                RuleIdentifier: "nested-not-condition",
                Title: "Nested Not Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 14,
                LinePosition: 38,
                Path: "properties.policyRule.if.anyOf[1].not.not",
                Description: "Two nested 'not' operators negate the same condition, which adds nesting without changing the result. Remove both.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_NestedNotCondition_TripleNot()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedNotCondition()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""not"": {
                            ""not"": {
                              ""field"": ""location"",
                              ""equals"": ""eastus""
                            }
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "nested-not-condition",
                Title: "Nested Not Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 36,
                Path: "properties.policyRule.if.not.not.not",
                Description: "Two nested 'not' operators negate the same condition, which adds nesting without changing the result. Remove both.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_NestedNotCondition_SingleNot_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedNotCondition()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""field"": ""location"",
                          ""equals"": ""eastus""
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
        public void RuleTests_NestedNotCondition_NotSeparatedByAllOf_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedNotCondition()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""allOf"": [
                            {
                              ""not"": {
                                ""field"": ""location"",
                                ""equals"": ""eastus""
                              }
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

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NestedNotCondition_NotSeparatedByAnyOf_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NestedNotCondition()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""not"": {
                          ""anyOf"": [
                            {
                              ""not"": {
                                ""field"": ""location"",
                                ""equals"": ""eastus""
                              }
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

            results.Should().BeEmpty();
        }
    }
}
