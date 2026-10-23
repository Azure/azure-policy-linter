namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="OptionalFieldAlias"/> rule.
    /// </summary>
    public class OptionalFieldAliasTests
    {
        private const int MaximumDescriptionLength = 400;

        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        /// <summary>
        /// A single affected alias keeps its reference location.
        /// </summary>
        [Fact]
        public void RuleTests_OptionalFieldAlias_SingleAlias_PreservesReferenceLocation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: OptionalFieldAliasTests.TypeMetadata);

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
                Severity: Severity.Informational,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 94,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "Properties mapped by these aliases may be absent from requests and cause unexpected policy evaluation: 'Microsoft.Storage/storageAccounts/allowBlobPublicAccess': 2026-04-01, 2025-08-01, and 17 older API versions.");
            results.Should().ContainEquivalentOf(output);
        }

        /// <summary>
        /// Multiple aliases are aggregated and duplicate references are removed.
        /// </summary>
        /// <param name="duplicateAlias">The repeated alias.</param>
        [Theory]
        [InlineData("Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration")]
        [InlineData("microsoft.compute/virtualmachines/osprofile.windowsconfiguration")]
        public void RuleTests_OptionalFieldAlias_MultipleAliases_AggregatesAndDeduplicates(string duplicateAlias)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: OptionalFieldAliasTests.TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration"",
                            ""exists"": ""true""
                          },
                          {
                            ""field"": ""Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType"",
                            ""equals"": ""Windows""
                          },
                          {
                            ""field"": ""Microsoft.ConnectedVMwarevSphere/virtualMachines/osProfile.osType"",
                            ""equals"": ""Windows""
                          },
                          {
                            ""field"": """ + duplicateAlias + @""",
                            ""exists"": ""false""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "optional-field-alias",
                Title: "Optional Field Alias",
                Severity: Severity.Informational,
                Category: Category.ResourceFields,
                LineNumber: 6,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: "Properties mapped by these aliases may be absent from requests and cause unexpected policy evaluation: 'Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration' and 1 more alias: 2025-11-01, 2025-04-01, and 26 older API versions; and 1 more affected alias.");

            results.Should().ContainEquivalentOf(output);
            results[0].Description.Length.Should().BeLessThanOrEqualTo(400);
        }

        /// <summary>
        /// Long alias lists are summarized within the description limit.
        /// </summary>
        [Fact]
        public void RuleTests_OptionalFieldAlias_ManyAliases_SummarizesWithinDescriptionLimit()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: new OptionalAliasTypeMetadata());

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""Microsoft.Test/widgets/group-one-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"",
                            ""exists"": ""true""
                          },
                          {
                            ""field"": ""Microsoft.Test/widgets/group-one-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"",
                            ""exists"": ""true""
                          },
                          {
                            ""field"": ""Microsoft.Test/widgets/group-two-dddddddddddddddddddddddddddddddddddddddd"",
                            ""exists"": ""true""
                          },
                          {
                            ""field"": ""Microsoft.Test/widgets/group-two-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"",
                            ""exists"": ""true""
                          },
                          {
                            ""field"": ""Microsoft.Test/widgets/group-three-ffffffffffffffffffffffffffffffffffffffff"",
                            ""exists"": ""true""
                          },
                          {
                            ""field"": ""Microsoft.Test/widgets/group-three-gggggggggggggggggggggggggggggggggggggggg"",
                            ""exists"": ""true""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "optional-field-alias",
                Title: "Optional Field Alias",
                Severity: Severity.Informational,
                Category: Category.ResourceFields,
                LineNumber: 6,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: "Properties mapped by these aliases may be absent from requests and cause unexpected policy evaluation: 'Microsoft.Test/widgets/group-one-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' and 1 more alias: 2025-01-01, 2024-01-01, and 1 older API version; and 4 more affected aliases.");

            results.Should().ContainEquivalentOf(output);
            results[0].Description.Length.Should().BeLessThanOrEqualTo(400);
        }

        /// <summary>
        /// A later subset is selected when the first subset cannot fit.
        /// </summary>
        [Fact]
        public void RuleTests_OptionalFieldAlias_FirstSubsetTooLong_SelectsLaterSubset()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: new OptionalAliasTypeMetadata());

            var longAlias = "Microsoft.Test/widgets/" + new string('a', 400);
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": """ + longAlias + @""",
                            ""exists"": ""true""
                          },
                          {
                            ""field"": ""Microsoft.Test/widgets/group-two-property"",
                            ""exists"": ""true""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "optional-field-alias",
                Title: "Optional Field Alias",
                Severity: Severity.Informational,
                Category: Category.ResourceFields,
                LineNumber: 6,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: "Properties mapped by these aliases may be absent from requests and cause unexpected policy evaluation: 'Microsoft.Test/widgets/group-two-property': 2025-01-01, 2024-01-01; and 1 more affected alias.");

            results.Should().ContainEquivalentOf(output);
            results[0].Description.Length.Should().BeLessThanOrEqualTo(400);
        }

        /// <summary>
        /// A long alias is truncated when no complete subset can fit.
        /// </summary>
        [Fact]
        public void RuleTests_OptionalFieldAlias_NoSubsetFits_TruncatesAliasAtDescriptionLimit()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: new OptionalAliasTypeMetadata());

            var longAlias = "Microsoft.Test/widgets/" + new string('a', 400);
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": """ + longAlias + @""",
                        ""exists"": ""true""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            const string descriptionPrefix = "Properties mapped by these aliases may be absent from requests and cause unexpected policy evaluation: '";
            const string descriptionSuffix = "': 2025-01-01.";
            var expectedAliasLength =
                OptionalFieldAliasTests.MaximumDescriptionLength -
                descriptionPrefix.Length -
                descriptionSuffix.Length;
            var expectedAlias = $"{longAlias.Substring(startIndex: 0, length: expectedAliasLength - 3)}...";
            var expectedDescription = $"{descriptionPrefix}{expectedAlias}{descriptionSuffix}";

            results[0].Description.Should().Be(expectedDescription);
            results[0].Description.Should().HaveLength(OptionalFieldAliasTests.MaximumDescriptionLength);
        }

        /// <summary>
        /// Different complete version sets remain separate when their summaries match.
        /// </summary>
        [Fact]
        public void RuleTests_OptionalFieldAlias_MatchingSummaries_DoesNotMergeDifferentVersionSets()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: new OptionalAliasTypeMetadata());

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""Microsoft.Test/widgets/group-one-property"",
                            ""exists"": ""true""
                          },
                          {
                            ""field"": ""Microsoft.Test/widgets/group-four-property"",
                            ""exists"": ""true""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "optional-field-alias",
                Title: "Optional Field Alias",
                Severity: Severity.Informational,
                Category: Category.ResourceFields,
                LineNumber: 6,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: "Properties mapped by these aliases may be absent from requests and cause unexpected policy evaluation: 'Microsoft.Test/widgets/group-four-property': 2025-01-01, 2024-01-01, and 1 older API version; 'Microsoft.Test/widgets/group-one-property': 2025-01-01, 2024-01-01, and 1 older API version.");

            results.Should().ContainEquivalentOf(output);
            results[0].Description.Length.Should().BeLessThanOrEqualTo(OptionalFieldAliasTests.MaximumDescriptionLength);
        }

        /// <summary>
        /// Required properties do not produce a finding.
        /// </summary>
        [Fact]
        public void RuleTests_OptionalFieldAlias_RequiredProperty_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: OptionalFieldAliasTests.TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.KeyVault/vaults""
                          },
                          {
                            ""field"": ""Microsoft.KeyVault/vaults/sku.name"",
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

            results.Should().BeEmpty();
        }

        /// <summary>
        /// Read-only properties remain owned by the read-only rule.
        /// </summary>
        [Fact]
        public void RuleTests_OptionalFieldAlias_ReadOnlyProperty_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: OptionalFieldAliasTests.TypeMetadata);

            // privateEndpointConnections is read-only (and not required), so the read-only-field-alias
            // rule owns it; optional-field-alias must stay silent as the residual case.
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
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

            results.Should().BeEmpty();
        }

        /// <summary>
        /// Unresolved references do not produce a finding.
        /// </summary>
        [Fact]
        public void RuleTests_OptionalFieldAlias_UnresolvedReference_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: OptionalFieldAliasTests.TypeMetadata);

            // "location" is a policy field, not a resource-property alias, so the rule short-circuits.
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""location"",
                        ""equals"": ""eastus""
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

        /// <summary>
        /// Provides optional-property metadata for test aliases.
        /// </summary>
        private sealed class OptionalAliasTypeMetadata : ITypeMetadata
        {
            /// <inheritdoc/>
            public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
            {
                if (!aliasName.StartsWith("Microsoft.Test/widgets/", StringComparison.OrdinalIgnoreCase))
                {
                    result = Array.Empty<ResourcePropertyMetadata>();
                    return false;
                }

                string[] apiVersions;
                if (aliasName.Contains("group-one", StringComparison.OrdinalIgnoreCase))
                {
                    apiVersions = new[] { "2023-01-01", "2024-01-01", "2025-01-01" };
                }
                else if (aliasName.Contains("group-four", StringComparison.OrdinalIgnoreCase))
                {
                    apiVersions = new[] { "2022-01-01", "2024-01-01", "2025-01-01" };
                }
                else if (aliasName.Contains("group-two", StringComparison.OrdinalIgnoreCase))
                {
                    apiVersions = new[] { "2024-01-01", "2025-01-01" };
                }
                else
                {
                    apiVersions = new[] { "2025-01-01" };
                }

                result = new[]
                {
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: apiVersions,
                        exists: true),
                };

                return true;
            }
        }
    }
}
