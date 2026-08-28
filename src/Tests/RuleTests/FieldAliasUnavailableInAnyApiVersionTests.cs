// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using System.Collections.Immutable;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="FieldAliasUnavailableInAnyApiVersion"/> rule.
    /// </summary>
    public class FieldAliasUnavailableInAnyApiVersionTests
    {
        private const string Alias = "Microsoft.Test/widgets/property";
        private const string ResourceType = "Microsoft.Test/widgets";
        private static readonly ITypeMetadata RealTypeMetadata = new TypeMetadata(
            metadataProvider: new OfflineMetadataProvider(),
            aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_OneFalseMetadataEntry_Fires()
        {
            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: Alias),
                metadata: new TestTypeMetadata(
                    alias: Alias,
                    PropertyMetadata(exists: false, resourceType: ResourceType, apiVersion: "2024-01-01")));

            AssertSingleFinding(
                results: results,
                alias: Alias,
                resourceType: ResourceType,
                lineNumber: 7,
                linePosition: 50,
                path: "properties.policyRule.if.field");
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_RealAllMissingAlias_Fires()
        {
            const string alias = "Microsoft.AppPlatform/Spring/apps.persistentDisk.usedInGB";
            const string resourceType = "Microsoft.AppPlatform/Spring";

            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: alias),
                metadata: FieldAliasUnavailableInAnyApiVersionTests.RealTypeMetadata);

            AssertSingleFinding(
                results: results,
                alias: alias,
                resourceType: resourceType,
                lineNumber: 7,
                linePosition: 76,
                path: "properties.policyRule.if.field");
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_AliasCasing_Fires()
        {
            const string policyAlias = "microsoft.test/WIDGETS/PROPERTY";

            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: policyAlias),
                metadata: new TestTypeMetadata(
                    alias: Alias,
                    PropertyMetadata(exists: false, resourceType: ResourceType, apiVersion: "2024-01-01")));

            AssertSingleFinding(
                results: results,
                alias: policyAlias,
                resourceType: "microsoft.test/WIDGETS",
                lineNumber: 7,
                linePosition: 50,
                path: "properties.policyRule.if.field");
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_MultipleFalseMetadataEntries_Fires()
        {
            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: Alias),
                metadata: new TestTypeMetadata(
                    alias: Alias,
                    PropertyMetadata(exists: false, resourceType: "Microsoft.Test/widgets/zeta", apiVersion: "2023-01-01"),
                    PropertyMetadata(exists: false, resourceType: "Microsoft.Test/widgets/alpha", apiVersion: "2024-01-01")));

            AssertSingleFinding(
                results: results,
                alias: Alias,
                resourceType: ResourceType,
                lineNumber: 7,
                linePosition: 50,
                path: "properties.policyRule.if.field");
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_FieldFunctionReference_Fires()
        {
            var results = Lint(
                policyDefinition: FieldFunctionPolicy(alias: Alias),
                metadata: new TestTypeMetadata(
                    alias: Alias,
                    PropertyMetadata(exists: false, resourceType: ResourceType, apiVersion: "2024-01-01")));

            AssertSingleFinding(
                results: results,
                alias: Alias,
                resourceType: ResourceType,
                lineNumber: 7,
                linePosition: 61,
                path: "properties.policyRule.if.value");
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_CurrentFunctionReference_Fires()
        {
            const string arrayAlias = "Microsoft.Test/widgets/items[*]";
            const string currentAlias = "Microsoft.Test/widgets/items[*].property";

            var results = Lint(
                policyDefinition: CurrentFunctionPolicy(arrayAlias: arrayAlias, currentAlias: currentAlias),
                metadata: new TestTypeMetadata(
                    alias: currentAlias,
                    PropertyMetadata(exists: false, resourceType: ResourceType, apiVersion: "2024-01-01")));

            results.Should().HaveCount(2);
            results.Should().ContainEquivalentOf(ExpectedOutput(
                alias: currentAlias,
                resourceType: ResourceType,
                lineNumber: 10,
                linePosition: 76,
                path: "properties.policyRule.if.count.where.value"));
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_OneTrueMetadataEntry_DoesNotFire()
        {
            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: Alias),
                metadata: new TestTypeMetadata(
                    alias: Alias,
                    PropertyMetadata(exists: false, resourceType: ResourceType, apiVersion: "2023-01-01"),
                    PropertyMetadata(exists: true, resourceType: ResourceType, apiVersion: "2024-01-01")));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_AllTrueMetadataEntries_DoNotFire()
        {
            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: Alias),
                metadata: new TestTypeMetadata(
                    alias: Alias,
                    PropertyMetadata(exists: true, resourceType: ResourceType, apiVersion: "2023-01-01"),
                    PropertyMetadata(exists: true, resourceType: ResourceType, apiVersion: "2024-01-01")));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_EmptyMetadata_Fires()
        {
            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: Alias),
                metadata: new TestTypeMetadata(alias: Alias));

            AssertSingleFinding(
                results: results,
                alias: Alias,
                resourceType: ResourceType,
                lineNumber: 7,
                linePosition: 50,
                path: "properties.policyRule.if.field");
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_BlankMetadataResourceTypes_UseAliasResourceType()
        {
            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: Alias),
                metadata: new TestTypeMetadata(
                    alias: Alias,
                    PropertyMetadata(exists: false, resourceType: string.Empty, apiVersion: "2023-01-01"),
                    PropertyMetadata(exists: false, resourceType: "   ", apiVersion: "2024-01-01")));

            AssertSingleFinding(
                results: results,
                alias: Alias,
                resourceType: ResourceType,
                lineNumber: 7,
                linePosition: 50,
                path: "properties.policyRule.if.field");
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_UnresolvedDynamicField_DoesNotFire()
        {
            var results = Lint(
                policyDefinition: DynamicFieldPolicy(),
                metadata: new TestTypeMetadata(
                    alias: Alias,
                    PropertyMetadata(exists: false, resourceType: ResourceType, apiVersion: "2024-01-01")));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_GenericField_DoesNotFire()
        {
            const string genericField = "type";

            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: genericField),
                metadata: new TestTypeMetadata(
                    alias: genericField,
                    PropertyMetadata(exists: false, resourceType: ResourceType, apiVersion: "2024-01-01")));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_NonAliasField_DoesNotFire()
        {
            const string nonAliasField = "tags['environment']";

            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: nonAliasField),
                metadata: new TestTypeMetadata(
                    alias: nonAliasField,
                    PropertyMetadata(exists: false, resourceType: ResourceType, apiVersion: "2024-01-01")));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasUnavailableInAnyApiVersion_AllFalseMetadata_OnlyThisRuleFires()
        {
            var results = Lint(
                policyDefinition: SingleFieldPolicy(field: Alias),
                metadata: new TestTypeMetadata(
                    alias: Alias,
                    PropertyMetadata(exists: false, resourceType: ResourceType, apiVersion: "2023-01-01"),
                    PropertyMetadata(exists: false, resourceType: ResourceType, apiVersion: "2024-01-01")),
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInAnyApiVersion(),
                    new FieldAliasUnavailableInLatestApiVersion(),
                    new FieldAliasUnavailableInOldApiVersions(),
                });

            AssertSingleFinding(
                results: results,
                alias: Alias,
                resourceType: ResourceType,
                lineNumber: 7,
                linePosition: 50,
                path: "properties.policyRule.if.field");
        }

        private static LinterOutput[] Lint(
            string policyDefinition,
            ITypeMetadata metadata,
            ILinterRule[] rules = null)
        {
            var linter = new PolicyLinter(
                rules: rules ?? new ILinterRule[]
                {
                    new FieldAliasUnavailableInAnyApiVersion(),
                },
                metadata: metadata);

            return linter.Lint(policyDefinition);
        }

        private static void AssertSingleFinding(
            LinterOutput[] results,
            string alias,
            string resourceType,
            int lineNumber,
            int linePosition,
            string path)
        {
            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(ExpectedOutput(
                alias: alias,
                resourceType: resourceType,
                lineNumber: lineNumber,
                linePosition: linePosition,
                path: path));
        }

        private static LinterOutput ExpectedOutput(
            string alias,
            string resourceType,
            int lineNumber,
            int linePosition,
            string path)
        {
            return new LinterOutput(
                RuleIdentifier: "field-alias-unavailable-in-any-api-version",
                Title: "Field Alias Unavailable in Any API Version",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: lineNumber,
                LinePosition: linePosition,
                Path: path,
                Description:
                    $"The field alias '{alias}' maps to an unknown property on resource type '{resourceType}', according to the linter's embedded metadata. " +
                    "Verify that the property exists on the target resource.");
        }

        private static ResourcePropertyMetadata PropertyMetadata(
            bool exists,
            string resourceType,
            string apiVersion)
        {
            return new ResourcePropertyMetadata
            {
                Exists = exists,
                ResourceType = resourceType,
                ApiVersions = ImmutableArray.Create(apiVersion),
            };
        }

        private static string SingleFieldPolicy(string field) => @"
{
  ""properties"": {
    ""mode"": ""Indexed"",
    ""policyRule"": {
      ""if"": {
        ""field"": """ + field + @""",
        ""equals"": ""value""
      },
      ""then"": {
        ""effect"": ""deny""
      }
    }
  }
}";

        private static string FieldFunctionPolicy(string alias) => @"
{
  ""properties"": {
    ""mode"": ""Indexed"",
    ""policyRule"": {
      ""if"": {
        ""value"": ""[field('" + alias + @"')]"",
        ""equals"": ""value""
      },
      ""then"": {
        ""effect"": ""deny""
      }
    }
  }
}";

        private static string CurrentFunctionPolicy(string arrayAlias, string currentAlias) => @"
{
  ""properties"": {
    ""mode"": ""Indexed"",
    ""policyRule"": {
      ""if"": {
        ""count"": {
          ""field"": """ + arrayAlias + @""",
          ""where"": {
            ""value"": ""[current('" + currentAlias + @"')]"",
            ""equals"": ""value""
          }
        },
        ""greater"": 0
      },
      ""then"": {
        ""effect"": ""deny""
      }
    }
  }
}";

        private static string DynamicFieldPolicy() => @"
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
        ""equals"": ""value""
      },
      ""then"": {
        ""effect"": ""deny""
      }
    }
  }
}";

        private sealed class TestTypeMetadata : ITypeMetadata
        {
            private readonly string alias;
            private readonly ResourcePropertyMetadata[] metadata;

            public TestTypeMetadata(string alias, params ResourcePropertyMetadata[] metadata)
            {
                this.alias = alias;
                this.metadata = metadata;
            }

            public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
            {
                if (string.Equals(aliasName, this.alias, StringComparison.OrdinalIgnoreCase))
                {
                    result = this.metadata;
                    return true;
                }

                result = Array.Empty<ResourcePropertyMetadata>();
                return false;
            }
        }
    }
}
