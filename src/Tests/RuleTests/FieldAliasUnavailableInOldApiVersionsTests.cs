namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using System.Collections.Immutable;
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="FieldAliasUnavailableInOldApiVersions"/> rule.
    /// </summary>
    public class FieldAliasUnavailableInOldApiVersionsTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        /// <summary>
        /// Lints a policy with the old-API-version rule.
        /// </summary>
        /// <param name="policyDefinition">The policy definition.</param>
        /// <returns>The linter outputs.</returns>
        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInOldApiVersions()
                },
                metadata: FieldAliasUnavailableInOldApiVersionsTests.TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        /// <summary>
        /// An alias missing in the latest API version but present in older versions (deprecated) belongs to the
        /// latest-version rule and must not fire this rule, so the latest version is never listed as an old version.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_DeprecatedInLatest_DoesNotFire()
        {
            var results = FieldAliasUnavailableInOldApiVersionsTests.Lint(
                FieldAliasUnavailableInOldApiVersionsTests.SingleFieldPolicy(
                    field: "Microsoft.DocumentDB/databaseAccounts/ipRangeFilter"));

            results.Should().BeEmpty();
        }

        /// <summary>
        /// An alias that exists in every API version must not fire.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_PresentInAllVersions_DoesNotFire()
        {
            var results = FieldAliasUnavailableInOldApiVersionsTests.Lint(
                FieldAliasUnavailableInOldApiVersionsTests.SingleFieldPolicy(
                    field: "Microsoft.DocumentDB/databaseAccounts/databaseAccountOfferType"));

            results.Should().BeEmpty();
        }

        /// <summary>
        /// An alias that is missing in every API version is owned by a dedicated rule and must not fire this one.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_MissingInAllVersions_DoesNotFire()
        {
            var results = FieldAliasUnavailableInOldApiVersionsTests.Lint(
                FieldAliasUnavailableInOldApiVersionsTests.SingleFieldPolicy(
                    field: "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/throughputSettings/default.resource.autopilotSettings.autoUpgradePolicy"));

            results.Should().BeEmpty();
        }

        /// <summary>
        /// A field name that is not a resolved alias (a non-alias field or a non-resolved field reference) must not fire.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_NonAliasAndNonResolvedReference_DoNotFire()
        {
            FieldAliasUnavailableInOldApiVersionsTests.Lint(
                FieldAliasUnavailableInOldApiVersionsTests.SingleFieldPolicy(field: "type"))
                .Should()
                .BeEmpty();

            var nonResolvedReference = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""fieldName"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[field(parameters('fieldName'))]"",
                        ""equals"": ""Allow""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            FieldAliasUnavailableInOldApiVersionsTests.Lint(nonResolvedReference).Should().BeEmpty();
        }

        /// <summary>
        /// A single affected alias keeps its reference location.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_SingleAlias_PreservesReferenceLocation()
        {
            var results = FieldAliasUnavailableInOldApiVersionsTests.Lint(
                FieldAliasUnavailableInOldApiVersionsTests.SingleFieldPolicy(
                    field: "Microsoft.Storage/storageAccounts/networkAcls.defaultAction"));

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 90,
                Path: "properties.policyRule.if.field",
                Description: "These aliases are unavailable in older API versions, which can cause unexpected policy evaluation: 'Microsoft.Storage/storageAccounts/networkAcls.defaultAction': unavailable in 2016-12-01, 2016-05-01, and 3 older API versions (available in 25 newer API versions).");

            results.Should().ContainEquivalentOf(output);
        }

        /// <summary>
        /// One newer available version uses singular wording.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_OneNewerVersion_UsesSingularWording()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInOldApiVersions()
                },
                metadata: new UnavailableAliasTypeMetadata());

            var results = linter.Lint(
                FieldAliasUnavailableInOldApiVersionsTests.SingleFieldPolicy(
                    field: "Microsoft.Test/widgets/property"));

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 62,
                Path: "properties.policyRule.if.field",
                Description: "These aliases are unavailable in older API versions, which can cause unexpected policy evaluation: 'Microsoft.Test/widgets/property': unavailable in 2024-01-01 (available in 1 newer API version).");

            results.Should().ContainEquivalentOf(output);
        }

        /// <summary>
        /// Matching aliases share a group and different newer-version counts remain separate.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_MatchingAndDifferentContexts_GroupsOnlyMatchingAliases()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInOldApiVersions()
                },
                metadata: new UnavailableAliasTypeMetadata());

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""Microsoft.Test/widgets/property-one-a"",
                            ""exists"": ""true""
                          },
                          {
                            ""field"": ""Microsoft.Test/widgets/property-one-b"",
                            ""exists"": ""true""
                          },
                          {
                            ""field"": ""Microsoft.Test/widgets/property-two"",
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
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 6,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: "These aliases are unavailable in older API versions, which can cause unexpected policy evaluation: 'Microsoft.Test/widgets/property-one-a', 'Microsoft.Test/widgets/property-one-b': unavailable in 2024-01-01 (available in 1 newer API version); 'Microsoft.Test/widgets/property-two': unavailable in 2024-01-01 (available in 2 newer API versions).");

            results.Should().ContainEquivalentOf(output);
        }

        /// <summary>
        /// Multiple aliases are aggregated and duplicate references are removed.
        /// </summary>
        /// <param name="duplicateAlias">The repeated alias.</param>
        [Theory]
        [InlineData("Microsoft.Storage/storageAccounts/networkAcls.defaultAction")]
        [InlineData("microsoft.storage/storageaccounts/networkacls.defaultaction")]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_MultipleAliases_AggregatesAndDeduplicates(string duplicateAlias)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInOldApiVersions()
                },
                metadata: FieldAliasUnavailableInOldApiVersionsTests.TypeMetadata);

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
                          },
                          {
                            ""field"": """ + duplicateAlias + @""",
                            ""notEquals"": ""Deny""
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 11,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: "These aliases are unavailable in older API versions, which can cause unexpected policy evaluation: 'Microsoft.Storage/storageAccounts/networkAcls.defaultAction' and 3 more aliases: unavailable in 2016-12-01, 2016-05-01, and 3 older API versions (available in 25 newer API versions).");

            results.Should().ContainEquivalentOf(output);
            results[0].Description.Length.Should().BeLessThanOrEqualTo(400);
        }

        /// <summary>
        /// Creates a policy with one field condition.
        /// </summary>
        /// <param name="field">The field name.</param>
        /// <returns>The policy definition.</returns>
        private static string SingleFieldPolicy(string field) => @"
            {
              ""properties"": {
                ""mode"": ""Indexed"",
                ""policyRule"": {
                  ""if"": {
                    ""field"": """ + field + @""",
                    ""equals"": ""Allow""
                  },
                  ""then"": {
                    ""effect"": ""deny""
                  }
                }
              }
            }";

        /// <summary>
        /// Provides unavailable-property metadata for a test alias.
        /// </summary>
        private sealed class UnavailableAliasTypeMetadata : ITypeMetadata
        {
            /// <inheritdoc/>
            public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
            {
                if (!aliasName.StartsWith("Microsoft.Test/widgets/property", StringComparison.OrdinalIgnoreCase))
                {
                    result = Array.Empty<ResourcePropertyMetadata>();
                    return false;
                }

                var availableApiVersions = aliasName.EndsWith("-two", StringComparison.OrdinalIgnoreCase)
                    ? ImmutableArray.Create("2025-01-01", "2026-01-01")
                    : ImmutableArray.Create("2025-01-01");

                result = new[]
                {
                    new ResourcePropertyMetadata
                    {
                        ResourceType = "Microsoft.Test/widgets",
                        ApiVersions = ImmutableArray.Create("2024-01-01"),
                        Exists = false,
                    },
                    new ResourcePropertyMetadata
                    {
                        ResourceType = "Microsoft.Test/widgets",
                        ApiVersions = availableApiVersions,
                        Exists = true,
                    },
                };

                return true;
            }
        }
    }
}
