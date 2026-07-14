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
    /// Tests for the <see cref="FieldAliasUnavailableInLatestApiVersion"/> rule.
    /// </summary>
    public class FieldAliasUnavailableInLatestApiVersionTests
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
                    new FieldAliasUnavailableInLatestApiVersion()
                },
                metadata: TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        /// <summary>
        /// An alias that is missing in the latest API version but present in older versions (deprecated) must fire.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInLatestApiVersion_DeprecatedInLatest_Fires()
        {
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

            var results = Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-latest-api-version",
                Title: "Field Alias Unavailable In Latest API Version",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 90,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.DocumentDB/databaseAccounts/ipRangeFilter' is referring to a property that doesn't exist in the latest API version (2025-11-01-preview) of resource type: 'Microsoft.DocumentDB/databaseAccounts'. The policy might not work as intended.");

            results.Should().ContainEquivalentOf(output);
        }

        /// <summary>
        /// An alias that exists in the latest API version but is missing in an older version (the old-versions rule's
        /// case) must not fire this rule.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInLatestApiVersion_PresentInLatestMissingInOld_DoesNotFire()
        {
            var results = Lint(SingleFieldPolicy(field: "Microsoft.Storage/storageAccounts/networkAcls.defaultAction"));

            results.Should().BeEmpty();
        }

        /// <summary>
        /// An alias that exists in every API version must not fire.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInLatestApiVersion_PresentInAllVersions_DoesNotFire()
        {
            var results = Lint(SingleFieldPolicy(field: "Microsoft.DocumentDB/databaseAccounts/databaseAccountOfferType"));

            results.Should().BeEmpty();
        }

        /// <summary>
        /// An alias that is missing in every API version is owned by a dedicated rule and must not fire this one.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInLatestApiVersion_MissingInAllVersions_DoesNotFire()
        {
            var results = Lint(SingleFieldPolicy(field: "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/throughputSettings/default.resource.autopilotSettings.autoUpgradePolicy"));

            results.Should().BeEmpty();
        }

        /// <summary>
        /// A field name that is not a resolved alias (a non-alias field or a non-resolved field reference) must not fire.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasUnavailableInLatestApiVersion_NonAliasAndNonResolvedReference_DoNotFire()
        {
            Lint(SingleFieldPolicy(field: "type")).Should().BeEmpty();

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

    }
}
