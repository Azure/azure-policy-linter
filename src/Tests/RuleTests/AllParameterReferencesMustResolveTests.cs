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
    /// Tests for the <see cref="AllParameterReferencesMustResolve"/> rule.
    /// </summary>
    public class AllParameterReferencesMustResolveTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        void RuleTests_AllParameterReferencesMustResolve_UnresolvedParameter()
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
        void RuleTests_AllParameterReferencesMustResolve_AllParametersResolved()
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
        void RuleTests_AllParameterReferencesMustResolve_CaseInsensitiveMatch()
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
        void RuleTests_AllParameterReferencesMustResolve_MultipleUnresolvedParameters()
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
        void RuleTests_AllParameterReferencesMustResolve_NoParameters()
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
        void RuleTests_AllParameterReferencesMustResolve_NoParameterReferences()
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
        void RuleTests_AllParameterReferencesMustResolve_ParameterInComplexExpression()
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
    }
}
