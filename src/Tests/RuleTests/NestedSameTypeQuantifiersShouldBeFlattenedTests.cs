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
    /// Tests for the <see cref="NestedSameTypeQuantifiersShouldBeFlattened"/> rule.
    /// </summary>
    public class NestedSameTypeQuantifiersShouldBeFlattenedTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        void LinterTests_NestedSameTypeQuantifiersShouldBeFlattened_AllOfInsideAllOf()
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
        void LinterTests_NestedSameTypeQuantifiersShouldBeFlattened_AnyOfInsideAnyOf()
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
        void LinterTests_NestedSameTypeQuantifiersShouldBeFlattened_AllOfInsideAnyOf_NoViolation()
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
        void LinterTests_NestedSameTypeQuantifiersShouldBeFlattened_NoNestedQuantifier_NoViolation()
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
        void LinterTests_NestedSameTypeQuantifiersShouldBeFlattened_MultipleNestedAllOf()
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
        void LinterTests_NestedSameTypeQuantifiersShouldBeFlattened_NotQuantifier_NoViolation()
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
        void LinterTests_NestedSameTypeQuantifiersShouldBeFlattened_NestedAtIndexZero()
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
    }
}
