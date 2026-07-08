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
    /// Tests for the <see cref="TypeConditionFirstInAllOf"/> rule.
    /// </summary>
    public class TypeConditionFirstInAllOfTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        void LinterTests_TypeConditionFirstInAllOf_TypeIsFirst()
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
        void LinterTests_TypeConditionFirstInAllOf_TypeIsNotFirst()
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
        void LinterTests_TypeConditionFirstInAllOf_TypeAtIndexTwo()
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
        void LinterTests_TypeConditionFirstInAllOf_NoTypeCondition()
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
        void LinterTests_TypeConditionFirstInAllOf_SingleConditionAllOf()
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
        void LinterTests_TypeConditionFirstInAllOf_AnyOfNotChecked()
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
        void LinterTests_TypeConditionFirstInAllOf_CaseInsensitive()
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
    }
}
