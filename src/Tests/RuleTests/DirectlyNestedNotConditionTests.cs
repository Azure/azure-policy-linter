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
    /// Tests for the <see cref="DirectlyNestedNotCondition"/> rule.
    /// </summary>
    public class DirectlyNestedNotConditionTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_DirectlyNestedNotCondition_SimpleDoubleNot()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DirectlyNestedNotCondition()
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
                RuleIdentifier: "directly-nested-not-condition",
                Title: "Directly Nested Not Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 34,
                Path: "properties.policyRule.if.not.not",
                Description: "The directly nested 'not' operators negate the same condition twice and are mechanically equivalent to the inner condition. Remove both directly nested 'not' operators.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_DirectlyNestedNotCondition_DoubleNotUnderAllOf()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DirectlyNestedNotCondition()
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
                RuleIdentifier: "directly-nested-not-condition",
                Title: "Directly Nested Not Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 14,
                LinePosition: 38,
                Path: "properties.policyRule.if.allOf[1].not.not",
                Description: "The directly nested 'not' operators negate the same condition twice and are mechanically equivalent to the inner condition. Remove both directly nested 'not' operators.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_DirectlyNestedNotCondition_DoubleNotUnderAnyOf()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DirectlyNestedNotCondition()
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
                RuleIdentifier: "directly-nested-not-condition",
                Title: "Directly Nested Not Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 14,
                LinePosition: 38,
                Path: "properties.policyRule.if.anyOf[1].not.not",
                Description: "The directly nested 'not' operators negate the same condition twice and are mechanically equivalent to the inner condition. Remove both directly nested 'not' operators.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_DirectlyNestedNotCondition_TripleNot()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DirectlyNestedNotCondition()
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

            results.Should().HaveCount(2);

            var outerPairOutput = new LinterOutput(
                RuleIdentifier: "directly-nested-not-condition",
                Title: "Directly Nested Not Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 34,
                Path: "properties.policyRule.if.not.not",
                Description: "The directly nested 'not' operators negate the same condition twice and are mechanically equivalent to the inner condition. Remove both directly nested 'not' operators.");

            var innerPairOutput = new LinterOutput(
                RuleIdentifier: "directly-nested-not-condition",
                Title: "Directly Nested Not Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 36,
                Path: "properties.policyRule.if.not.not.not",
                Description: "The directly nested 'not' operators negate the same condition twice and are mechanically equivalent to the inner condition. Remove both directly nested 'not' operators.");

            results.Should().ContainEquivalentOf(outerPairOutput);
            results.Should().ContainEquivalentOf(innerPairOutput);
        }

        [Fact]
        public void RuleTests_DirectlyNestedNotCondition_SingleNot_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DirectlyNestedNotCondition()
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
        public void RuleTests_DirectlyNestedNotCondition_NotSeparatedByAllOf_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DirectlyNestedNotCondition()
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
        public void RuleTests_DirectlyNestedNotCondition_NotSeparatedByAnyOf_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DirectlyNestedNotCondition()
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
