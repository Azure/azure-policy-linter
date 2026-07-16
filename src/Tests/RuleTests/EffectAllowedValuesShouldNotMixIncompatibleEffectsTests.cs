namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Newtonsoft.Json.Linq;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="EffectAllowedValuesShouldNotMixIncompatibleEffects"/> rule.
    /// </summary>
    public class EffectAllowedValuesShouldNotMixIncompatibleEffectsTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_ValidSameCategory()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Disabled""
                        ]
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_MixNoDetailsAndModify()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Modify"",
                          ""Disabled""
                        ]
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_MixNoDetailsAndIfNotExists()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""AuditIfNotExists"",
                        ""allowedValues"": [
                          ""Deny"",
                          ""AuditIfNotExists"",
                          ""Disabled""
                        ]
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_MixAllThreeCategories()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Modify"",
                          ""DeployIfNotExists"",
                          ""Disabled""
                        ]
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

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-allowed-values-should-not-mix-incompatible-effects",
                Title: "Effect Allowed Values Should Not Mix Incompatible Effects",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 23,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' has allowedValues that combine non-interchangeable effects: DeployIfNotExists, Modify. Use only effects that are interchangeable with the policy's 'then.details' configuration; 'Disabled' can be combined with any effect."));
        }

        [Fact]
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_IfNotExistsCategoryOnly()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""AuditIfNotExists"",
                        ""allowedValues"": [
                          ""AuditIfNotExists"",
                          ""DeployIfNotExists"",
                          ""Disabled""
                        ]
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_CaseInsensitive()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""audit"",
                        ""allowedValues"": [
                          ""audit"",
                          ""modify"",
                          ""deployIfNotExists"",
                          ""Disabled""
                        ]
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

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-allowed-values-should-not-mix-incompatible-effects",
                Title: "Effect Allowed Values Should Not Mix Incompatible Effects",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 23,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' has allowedValues that combine non-interchangeable effects: deployIfNotExists, modify. Use only effects that are interchangeable with the policy's 'then.details' configuration; 'Disabled' can be combined with any effect."));
        }

        [Fact]
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_NotParameterized()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
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
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_NoAllowedValues()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_OnlyUncategorizedEffects()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Disabled""
                        ]
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_CustomParameterName()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""policyEffect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Modify"",
                          ""DeployIfNotExists"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('policyEffect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-allowed-values-should-not-mix-incompatible-effects",
                Title: "Effect Allowed Values Should Not Mix Incompatible Effects",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 23,
                LinePosition: 64,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'policyEffect' has allowedValues that combine non-interchangeable effects: DeployIfNotExists, Modify. Use only effects that are interchangeable with the policy's 'then.details' configuration; 'Disabled' can be combined with any effect."));
        }

        [Fact]
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_CategorizedWithUncategorized()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Append"",
                          ""Disabled""
                        ]
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_MultipleValuesPerCategory()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Modify"",
                          ""Disabled""
                        ]
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_EmptyAllowedValues()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": []
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_ExplicitlyNullAllowedValues()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": null
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_NullAllowedValueWithConflict()
        {
            var parameterObject = new ParameterObject
            {
                Type = new GenericObjectProperty<string> { Value = "String" },
                AllowedValues = new GenericObjectProperty<GenericObjectProperty<JToken>[]>
                {
                    Value = new[]
                    {
                        new GenericObjectProperty<JToken> { Value = JValue.CreateNull() },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject("Modify") },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject("DeployIfNotExists") }
                    }
                }
            };

            var parameter = new Parameter(
                name: "effect",
                parameterProperty: new GenericObjectProperty<ParameterObject> { Value = parameterObject },
                path: ImmutableArray<string>.Empty,
                parent: null!);

            var context = new LinterContext(
                resourceTypeMetadata: TypeMetadata,
                parameters: ImmutableDictionary<string, Parameter>.Empty.Add(key: "effect", value: parameter));

            var then = new GenericObjectProperty<ThenObject>
            {
                Value = new ThenObject
                {
                    Effect = new GenericObjectProperty<string>
                    {
                        Value = "[parameters('effect')]",
                        LineNumber = 22,
                        LinePosition = 58
                    }
                }
            };

            var expression = new ThenExpression(
                then: then,
                parentPath: ImmutableArray.Create("properties", "policyRule"),
                parent: null!,
                typeMetadata: TypeMetadata);

            var rule = new EffectAllowedValuesShouldNotMixIncompatibleEffects();
            var results = rule.Evaluate(expression: expression, context: context);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-allowed-values-should-not-mix-incompatible-effects",
                Title: "Effect Allowed Values Should Not Mix Incompatible Effects",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' has allowedValues that combine non-interchangeable effects: DeployIfNotExists, Modify. Use only effects that are interchangeable with the policy's 'then.details' configuration; 'Disabled' can be combined with any effect."));
        }

        [Fact]
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_DataplaneModeSkipped()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Microsoft.Kubernetes.Data"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Modify"",
                          ""DeployIfNotExists"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.ContainerService/managedClusters""
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_UnknownEffectNoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""FutureEffect"",
                          ""Disabled""
                        ]
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
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_MixDenyActionAndModify()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""DenyAction"",
                        ""allowedValues"": [
                          ""DenyAction"",
                          ""Modify"",
                          ""Disabled""
                        ]
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

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-allowed-values-should-not-mix-incompatible-effects",
                Title: "Effect Allowed Values Should Not Mix Incompatible Effects",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' has allowedValues that combine non-interchangeable effects: DenyAction, Modify. Use only effects that are interchangeable with the policy's 'then.details' configuration; 'Disabled' can be combined with any effect."));
        }

        [Fact]
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_MixAppendAndModify()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Append"",
                        ""allowedValues"": [
                          ""Append"",
                          ""Modify"",
                          ""Disabled""
                        ]
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

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-allowed-values-should-not-mix-incompatible-effects",
                Title: "Effect Allowed Values Should Not Mix Incompatible Effects",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' has allowedValues that combine non-interchangeable effects: Append, Modify. Use only effects that are interchangeable with the policy's 'then.details' configuration; 'Disabled' can be combined with any effect."));
        }

        [Fact]
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_MixManualAndModify()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Manual"",
                        ""allowedValues"": [
                          ""Manual"",
                          ""Modify"",
                          ""Disabled""
                        ]
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

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-allowed-values-should-not-mix-incompatible-effects",
                Title: "Effect Allowed Values Should Not Mix Incompatible Effects",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' has allowedValues that combine non-interchangeable effects: Manual, Modify. Use only effects that are interchangeable with the policy's 'then.details' configuration; 'Disabled' can be combined with any effect."));
        }

        [Theory]
        [InlineData("Audit")]
        [InlineData("Deny")]
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_MixManualAndAuditOrDeny(string otherEffect)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Manual"",
                        ""allowedValues"": [
                          ""Manual"",
                          ""OTHER_EFFECT"",
                          ""Disabled""
                        ]
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

            policyDefinition = policyDefinition.Replace(oldValue: "OTHER_EFFECT", newValue: otherEffect);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-allowed-values-should-not-mix-incompatible-effects",
                Title: "Effect Allowed Values Should Not Mix Incompatible Effects",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: $"The effect parameter 'effect' has allowedValues that combine non-interchangeable effects: {otherEffect}, Manual. Use only effects that are interchangeable with the policy's 'then.details' configuration; 'Disabled' can be combined with any effect."));
        }

        [Fact]
        public void RuleTests_EffectAllowedValuesShouldNotMixIncompatibleEffects_MultipleEffectsInOneConflictingCategory()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectAllowedValuesShouldNotMixIncompatibleEffects()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""AuditIfNotExists"",
                        ""allowedValues"": [
                          ""AuditIfNotExists"",
                          ""DeployIfNotExists"",
                          ""Modify"",
                          ""Disabled""
                        ]
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

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-allowed-values-should-not-mix-incompatible-effects",
                Title: "Effect Allowed Values Should Not Mix Incompatible Effects",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 23,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' has allowedValues that combine non-interchangeable effects: AuditIfNotExists, DeployIfNotExists, Modify. Use only effects that are interchangeable with the policy's 'then.details' configuration; 'Disabled' can be combined with any effect."));
        }
    }
}
