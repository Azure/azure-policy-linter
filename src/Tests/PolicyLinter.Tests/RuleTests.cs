// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

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
    /// Test the implementation of linter rules.
    /// </summary>
    public class RuleTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        void LinterTests_Rules_FieldAliasUnavailableInOldApiVersions()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInOldApiVersions()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": { // L10
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""value"": ""[field('Microsoft.Storage/storageAccounts/networkAcls.defaultAction')]"",
                            ""equals"": ""Allow""
                          }, // L20
                          {
                            ""count"": {
                              ""field"": ""Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]"",
                              ""where"": {
                                ""allOf"": [
                                  {
                                    ""field"": ""Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].action"",
                                    ""notEquals"": ""deny""
                                  },
                                  { // L30
                                    ""count"": {
                                      ""value"": ""[parameters('approvedIpRanges')]"",
                                      ""name"": ""approvedIpRange"",
                                      ""where"": {
                                        ""value"": ""[ipRangeContains(current('approvedIpRange'), current('Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].value'))]"",
                                        ""equals"": true
                                      }
                                    },
                                    ""equals"": 0
                                  }
                                ]
                              }
                            },
                            ""greater"": 0
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

            results.Should().HaveCount(4);

            var output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 109,
                Path: "properties.policyRule.if.allOf[1].value",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.defaultAction' maps to property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);

            output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 23,
                LinePosition: 97,
                Path: "properties.policyRule.if.allOf[2].count.field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]' maps to property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);

            output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 27,
                LinePosition: 110,
                Path: "properties.policyRule.if.allOf[2].count.where.allOf[0].field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].action' maps to property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);

            output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 35,
                LinePosition: 171,
                Path: "properties.policyRule.if.allOf[2].count.where.allOf[1].count.where.value",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].value' maps to property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_Rules_FieldAliasUnavailableInLatestApiVersions()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInLatestApiVersion()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.DocumentDB/databaseAccounts""
                          },
                          {
                            ""field"": ""Microsoft.DocumentDB/databaseAccounts/ipRangeFilter"",
                            ""equals"": ""Allow""
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
                RuleIdentifier: "field-alias-unavailable-in-latest-api-version",
                Title: "Field Alias Unavailable In Latest API Version",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 90,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.DocumentDB/databaseAccounts/ipRangeFilter' is referring to a property that doesn't exist in the latest API version (2025-11-01-preview) of resource type: 'Microsoft.DocumentDB/databaseAccounts'. This most likely means that the referenced property is deprecated and the policy might not work as intended.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_Rules_ReadOnlyFieldAlias()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ReadOnlyFieldAlias()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/privateEndpointConnections"",
                            ""equals"": ""Something""
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
                RuleIdentifier: "read-only-field-alias",
                Title: "Read-Only Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 99,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/privateEndpointConnections' maps to property that is marked as read-only in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2019-06-01, 2020-08-01-preview, 2021-01-01, 2021-02-01, 2021-04-01, 2021-06-01, 2021-08-01, 2021-09-01, 2022-05-01, 2022-09-01, 2023-01-01, 2023-04-01, 2023-05-01, 2024-01-01, 2025-01-01, 2025-06-01, 2025-08-01, 2026-04-01'");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_Rules_OptionalOnlyFieldAlias()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"",
                            ""equals"": ""Something""
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
                RuleIdentifier: "optional-field-alias",
                Title: "Optional Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 94,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/allowBlobPublicAccess' maps to property path that marked as optional in some API version of resource type: 'Microsoft.Storage/storageAccounts' . API versions: '2019-04-01, 2019-06-01, 2020-08-01-preview, 2021-01-01, 2021-02-01, 2021-04-01, 2021-06-01, 2021-08-01, 2021-09-01, 2022-05-01, 2022-09-01, 2023-01-01, 2023-04-01, 2023-05-01, 2024-01-01, 2025-01-01, 2025-06-01, 2025-08-01, 2026-04-01'");
            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_Rules_ConditionalFieldAlias()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ConditionalFieldAlias()
                },
                metadata: TypeMetadata);

            // The "folderPath" property is only present in data factory triggers of type "BlobTrigger"
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.DataFactory/factories/triggers""
                          },
                          {
                            ""field"": ""Microsoft.DataFactory/factories/triggers/BlobTrigger.typeProperties.folderPath"",
                            ""equals"": ""Something""
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
                RuleIdentifier: "conditional-field-alias",
                Title: "Conditional Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 117,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.DataFactory/factories/triggers/BlobTrigger.typeProperties.folderPath' maps to property path that only exists in the target resource type: 'Microsoft.DataFactory/factories/triggers' if some conditions are met. In all other cases, the property might be missing. Affected API versions: '2017-09-01-preview, 2018-06-01'");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_Rules_HardCodedEnforcementPolicyEffect_EnforcementEffect()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new HardCodedEnforcementPolicyEffect()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"",
                            ""equals"": ""Something""
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
                RuleIdentifier: "hard-coded-policy-enforcement-effect",
                Title: "Hard-Coded Enforcement Policy Effect",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 24,
                LinePosition: 40,
                Path: "properties.policyRule.then.effect",
                Description: "The policy definition has a hard-coded enforcement effect: 'deny'. Consider adding an \"effect\" policy definition parameter with default value: 'audit' and allowed values: 'audit,deny,disabled' and replace the hard-coded effect with \"[parameters('effect')]\". Parameterizing the policy effect makes it easy reuse the policy as well as to follow safe deployment practices (start with audit, then enforce).");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("audit")]
        [InlineData("[parameters('whatever')]")]
        void LinterTests_Rules_HardCodedEnforcementPolicyEffect_ShouldNotBeTriggered(string effectValue)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new HardCodedEnforcementPolicyEffect()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"",
                            ""equals"": ""Something""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    } 
                  }
                }";

            // Replace the hard-coded effect with the provided value
            policyDefinition = policyDefinition.Replace("deny", effectValue);
            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_Rules_RiskyEffectParameterDefaultValue_ParameterizedEffectWithRiskyDefault()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                   new RiskyEffectParameterDefaultValue()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"  
               {  
                 ""properties"": {  
                   ""mode"": ""Indexed"",  
                   ""parameters"": {  
                     ""effect"": {  
                       ""type"": ""String"",  
                       ""defaultValue"": ""deny"",  
                       ""allowedValues"": [  
                         ""audit"",  
                         ""deny"",  
                         ""disabled""  
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

            var output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 57,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the default value of the reference parameter: 'effect' is: 'deny'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to: 'audit' and: 'audit,deny,disabled' as the parameter allowed values."
            );

            results.Should().ContainEquivalentOf(output);

            // Now try to get fancy and have the parameter name as a static language expression. Should still work.
            linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                   new RiskyEffectParameterDefaultValue()
                },
                metadata: TypeMetadata);

            policyDefinition = policyDefinition.Replace("[parameters('effect')]", "[parameters(concat('e', 'ffect'))]");
            results = linter.Lint(policyDefinition);
            results.Should().HaveCount(1);

            output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 69,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the default value of the reference parameter: 'effect' is: 'deny'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to: 'audit' and: 'audit,deny,disabled' as the parameter allowed values."
            );

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_Rules_UnnecessaryQuantifierWrapper_AllOfSingleExpression()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
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
                RuleIdentifier: "unnecessary-quantifier-wrapper",
                Title: "Unnecessary allOf/anyOf wrapper",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 34,
                Path: "properties.policyRule.if.allOf",
                Description: "The \"allOf\" contains a single expression and can be removed. Use the inner expression directly.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_Rules_UnnecessaryQuantifierWrapper_AnyOfSingleExpression()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
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
                RuleIdentifier: "unnecessary-quantifier-wrapper",
                Title: "Unnecessary allOf/anyOf wrapper",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 34,
                Path: "properties.policyRule.if.anyOf",
                Description: "The \"anyOf\" contains a single expression and can be removed. Use the inner expression directly.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_Rules_UnnecessaryQuantifierWrapper_AllOfMultipleExpressions_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
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
        void LinterTests_Rules_UnnecessaryQuantifierWrapper_AnyOfMultipleExpressions_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
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
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
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
        void LinterTests_Rules_UnnecessaryQuantifierWrapper_NoQuantifier_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Compute/virtualMachines""
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
        void LinterTests_Rules_UnnecessaryQuantifierWrapper_NotQuantifier_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
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
        void LinterTests_Rules_UnnecessaryQuantifierWrapper_EmptyAllOf_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnnecessaryQuantifierWrapper()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": []
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
        void LinterTests_CommonRules_LikeNotLikeWithoutWildcards_LikeWithoutWildcard()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LikeNotLikeWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": ""Microsoft.Compute/virtualMachines""
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
                RuleIdentifier: "like-notlike-without-wildcards",
                Title: "like/notLike Without Wildcards",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 67,
                Path: "properties.policyRule.if.like",
                Description: "The condition uses the 'like' operator with value 'Microsoft.Compute/virtualMachines' which contains no wildcards (* or ?). Use 'equals' for exact matching, which is more efficient and precise.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void LinterTests_CommonRules_LikeNotLikeWithoutWildcards_NotLikeWithoutWildcard()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LikeNotLikeWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""notLike"": ""Microsoft.Compute/virtualMachines""
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
                RuleIdentifier: "like-notlike-without-wildcards",
                Title: "like/notLike Without Wildcards",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 70,
                Path: "properties.policyRule.if.notLike",
                Description: "The condition uses the 'notLike' operator with value 'Microsoft.Compute/virtualMachines' which contains no wildcards (* or ?). Use 'notEquals' for exact matching, which is more efficient and precise.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("like", "Microsoft.Compute/*")]
        [InlineData("like", "Microsoft.Compute/virtual?achines")]
        [InlineData("notLike", "Microsoft.*/storageAccounts")]
        [InlineData("notLike", "Microsoft.Compute/virtual?achines")]
        void LinterTests_CommonRules_LikeNotLikeWithoutWildcards_WithWildcards_NoViolation(string operatorName, string operandValue)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LikeNotLikeWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""type"",
                        ""{operatorName}"": ""{operandValue}""
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void LinterTests_CommonRules_LikeNotLikeWithoutWildcards_ParameterizedValue_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LikeNotLikeWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""parameters"": {
                      ""pattern"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""like"": ""[parameters('pattern')]""
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
        [InlineData("equals")]
        [InlineData("notEquals")]
        [InlineData("contains")]
        [InlineData("in")]
        void LinterTests_CommonRules_LikeNotLikeWithoutWildcards_OtherOperators_NoViolation(string operatorName)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LikeNotLikeWithoutWildcards()
                },
                metadata: TypeMetadata);

            var operandValue = operatorName == "in"
                ? @"[""Microsoft.Compute/virtualMachines""]"
                : @"""Microsoft.Compute/virtualMachines""";

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""type"",
                        ""{operatorName}"": {operandValue}
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
