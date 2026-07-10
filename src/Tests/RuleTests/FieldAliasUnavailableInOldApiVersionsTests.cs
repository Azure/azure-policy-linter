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
    /// Tests for the <see cref="FieldAliasUnavailableInOldApiVersions"/> rule.
    /// </summary>
    public class FieldAliasUnavailableInOldApiVersionsTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInOldApiVersions()
                },
                metadata: TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        /// <summary>
        /// An alias missing in the latest API version but present in older versions (deprecated) belongs to the
        /// latest-version rule and must not fire this rule, so the latest version is never listed as an old version.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_DeprecatedInLatest_DoesNotFire()
        {
            var results = Lint(SingleFieldPolicy(alias: "Microsoft.DocumentDB/databaseAccounts/ipRangeFilter"));

            results.Should().BeEmpty();
        }

        /// <summary>
        /// An alias that exists in every API version must not fire.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_PresentInAllVersions_DoesNotFire()
        {
            var results = Lint(SingleFieldPolicy(alias: "Microsoft.DocumentDB/databaseAccounts/databaseAccountOfferType"));

            results.Should().BeEmpty();
        }

        /// <summary>
        /// An alias that is missing in every API version is owned by a dedicated rule and must not fire this one.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_MissingInAllVersions_DoesNotFire()
        {
            var results = Lint(SingleFieldPolicy(alias: "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/throughputSettings/default.resource.autopilotSettings.autoUpgradePolicy"));

            results.Should().BeEmpty();
        }

        /// <summary>
        /// A field name that is not a resolved alias (a non-alias field or a non-resolved field reference) must not fire.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions_NonAliasAndNonResolvedReference_DoNotFire()
        {
            Lint(SingleFieldPolicy(alias: "type")).Should().BeEmpty();

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

            Lint(nonResolvedReference).Should().BeEmpty();
        }

        private static string SingleFieldPolicy(string alias) => @"
            {
              ""properties"": {
                ""mode"": ""Indexed"",
                ""policyRule"": {
                  ""if"": {
                    ""field"": """ + alias + @""",
                    ""equals"": ""Allow""
                  },
                  ""then"": {
                    ""effect"": ""deny""
                  }
                }
              }
            }";

        [Fact]
        public void RuleTests_FieldAliasUnavailableInOldApiVersions()
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
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.defaultAction' maps to a property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);

            output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 23,
                LinePosition: 97,
                Path: "properties.policyRule.if.allOf[2].count.field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]' maps to a property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);

            output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 27,
                LinePosition: 110,
                Path: "properties.policyRule.if.allOf[2].count.where.allOf[0].field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].action' maps to a property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);

            output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-old-api-versions",
                Title: "Field Alias Unavailable In Old API Versions",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 35,
                LinePosition: 171,
                Path: "properties.policyRule.if.allOf[2].count.where.allOf[1].count.where.value",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].value' maps to a property path that doesn't exist in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2015-05-01-preview, 2015-06-15, 2016-01-01, 2016-05-01, 2016-12-01'");

            results.Should().ContainEquivalentOf(output);
        }
    }
}
