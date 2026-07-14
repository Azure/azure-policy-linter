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
        public void RuleTests_AllParameterReferencesMustResolve_UnresolvedParameter()
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
                Description: "The parameter 'efect' is referenced but is not declared in the policy's 'parameters' block, so the reference cannot resolve.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_AllParameterReferencesMustResolve_AllParametersResolved()
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
        public void RuleTests_AllParameterReferencesMustResolve_CaseInsensitiveMatch()
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
        public void RuleTests_AllParameterReferencesMustResolve_MultipleUnresolvedParameters()
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
                Description: "The parameter 'fieldName' is referenced but is not declared in the policy's 'parameters' block, so the reference cannot resolve."));

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "all-parameter-references-must-resolve",
                Title: "All Parameter References Must Resolve",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 14,
                LinePosition: 65,
                Path: "properties.policyRule.if.equals",
                Description: "The parameter 'expectedValue' is referenced but is not declared in the policy's 'parameters' block, so the reference cannot resolve."));
        }

        [Fact]
        public void RuleTests_AllParameterReferencesMustResolve_NoParametersBlock()
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

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "all-parameter-references-must-resolve",
                Title: "All Parameter References Must Resolve",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 11,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The parameter 'effect' is referenced but is not declared in the policy's 'parameters' block, so the reference cannot resolve."));
        }

        [Fact]
        public void RuleTests_AllParameterReferencesMustResolve_EmptyParametersBlock()
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
                    ""parameters"": {},
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

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "all-parameter-references-must-resolve",
                Title: "All Parameter References Must Resolve",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The parameter 'effect' is referenced but is not declared in the policy's 'parameters' block, so the reference cannot resolve."));
        }

        [Fact]
        public void RuleTests_AllParameterReferencesMustResolve_NestedParameterReference()
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
                    ""parameters"": {},
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""[field(parameters('fieldName'))]"",
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
                LineNumber: 8,
                LinePosition: 67,
                Path: "properties.policyRule.if.field",
                Description: "The parameter 'fieldName' is referenced but is not declared in the policy's 'parameters' block, so the reference cannot resolve."));
        }

        [Fact]
        public void RuleTests_AllParameterReferencesMustResolve_PropertySelectorOnUndefinedParameter()
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
                    ""parameters"": {},
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""[parameters('config').value]""
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
                LineNumber: 9,
                LinePosition: 64,
                Path: "properties.policyRule.if.equals",
                Description: "The parameter 'config' is referenced but is not declared in the policy's 'parameters' block, so the reference cannot resolve."));
        }

        [Fact]
        public void RuleTests_AllParameterReferencesMustResolve_NoParameterReferences()
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
        public void RuleTests_AllParameterReferencesMustResolve_ParameterInComplexExpression()
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
                Description: "The parameter 'tagNme' is referenced but is not declared in the policy's 'parameters' block, so the reference cannot resolve."));
        }
    }
}
