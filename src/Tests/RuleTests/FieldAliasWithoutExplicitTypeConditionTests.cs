// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using System.Collections.Generic;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="FieldAliasWithoutExplicitTypeCondition"/> rule.
    /// </summary>
    public class FieldAliasWithoutExplicitTypeConditionTests
    {
        private const string StorageAlias = "Contoso.Storage/accounts/setting";
        private const string OtherStorageAlias = "Contoso.Storage/accounts/otherSetting";
        private const string MultipleTypesAlias = "Contoso.Common/resources/setting";
        private const string FieldFunctionAlias = "Contoso.Network/virtualNetworks/setting";
        private const string CountArrayAlias = "Contoso.Storage/accounts/items[*]";
        private const string CurrentAlias = "Contoso.Storage/accounts/items[*].value";
        private const string EmptyMetadataAlias = "Contoso.Empty/resources/setting";
        private const string BlankResourceTypeAlias = "Contoso.Blank/resources/setting";

        private static readonly ITypeMetadata TypeMetadata = new TestTypeMetadata();
        private static readonly ITypeMetadata RealTypeMetadata = new TypeMetadata(
            metadataProvider: new OfflineMetadataProvider(),
            aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_OneAlias()
        {
            FieldAliasWithoutExplicitTypeConditionTests.AssertSingleFinding(
                ifCondition: $@"{{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}",
                resourceTypes: "Contoso.Storage/accounts");
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_MultipleAliasesSameType()
        {
            FieldAliasWithoutExplicitTypeConditionTests.AssertSingleFinding(
                ifCondition: $@"{{ ""allOf"": [{{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}, {{ ""field"": ""{OtherStorageAlias}"", ""equals"": ""enabled"" }}] }}",
                resourceTypes: "Contoso.Storage/accounts");
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_MultipleTypesAreSortedAndDeduplicated()
        {
            FieldAliasWithoutExplicitTypeConditionTests.AssertSingleFinding(
                ifCondition: $@"{{ ""allOf"": [{{ ""field"": ""{MultipleTypesAlias}"", ""equals"": ""enabled"" }}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}",
                resourceTypes: "Contoso.Compute/virtualMachines, Contoso.Storage/accounts");
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_FieldFunctionAlias()
        {
            FieldAliasWithoutExplicitTypeConditionTests.AssertSingleFinding(
                ifCondition: $@"{{ ""value"": ""[field('{FieldFunctionAlias}')]"", ""equals"": ""enabled"" }}",
                resourceTypes: "Contoso.Network/virtualNetworks");
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_CurrentFunctionAlias()
        {
            FieldAliasWithoutExplicitTypeConditionTests.AssertSingleFinding(
                ifCondition: $@"{{ ""count"": {{ ""field"": ""{CountArrayAlias}"", ""where"": {{ ""value"": ""[current('{CurrentAlias}')]"", ""equals"": ""enabled"" }} }}, ""greater"": 0 }}",
                resourceTypes: "Contoso.Storage/accounts");
        }

        [Theory]
        [InlineData(@"{ ""field"": ""type"", ""like"": ""Contoso.Storage/*"" }")]
        [InlineData(@"{ ""field"": ""type"", ""notEquals"": ""Contoso.Storage/accounts"" }")]
        [InlineData(@"{ ""field"": ""type"", ""notIn"": [""Contoso.Storage/accounts""] }")]
        [InlineData(@"{ ""field"": ""type"", ""equals"": ""[parameters('targetType')]"" }")]
        [InlineData(@"{ ""field"": ""type"", ""in"": ""[parameters('targetTypes')]"" }")]
        [InlineData(@"{ ""field"": ""type"", ""equals"": ""   "" }")]
        [InlineData(@"{ ""field"": ""type"", ""in"": [] }")]
        [InlineData(@"{ ""field"": ""type"", ""in"": ["""", ""   ""] }")]
        [InlineData(@"{ ""not"": { ""field"": ""type"", ""equals"": ""Contoso.Storage/accounts"" } }")]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_NonPositiveTypeCondition(string typeCondition)
        {
            FieldAliasWithoutExplicitTypeConditionTests.AssertSingleFinding(
                ifCondition: $@"{{ ""allOf"": [{typeCondition}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}",
                resourceTypes: "Contoso.Storage/accounts");
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_PositiveEquals()
        {
            var results = FieldAliasWithoutExplicitTypeConditionTests.Lint(
                ifCondition: $@"{{ ""allOf"": [{{ ""field"": ""TyPe"", ""equals"": ""Contoso.Storage/accounts"" }}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_PositiveValueFieldEquals()
        {
            var results = FieldAliasWithoutExplicitTypeConditionTests.Lint(
                ifCondition: $@"{{ ""allOf"": [{{ ""value"": ""[field('type')]"", ""equals"": ""Contoso.Storage/accounts"" }}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_PositiveNonEmptyIn()
        {
            var results = FieldAliasWithoutExplicitTypeConditionTests.Lint(
                ifCondition: $@"{{ ""allOf"": [{{ ""field"": ""type"", ""in"": ["""", ""Contoso.Storage/accounts""] }}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_DoubleNotPositiveEquals()
        {
            var results = FieldAliasWithoutExplicitTypeConditionTests.Lint(
                ifCondition: $@"{{ ""allOf"": [{{ ""not"": {{ ""not"": {{ ""field"": ""type"", ""equals"": ""Contoso.Storage/accounts"" }} }} }}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_NoAliases()
        {
            var results = FieldAliasWithoutExplicitTypeConditionTests.Lint(
                ifCondition: @"{ ""field"": ""location"", ""equals"": ""westus"" }");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_UnresolvedDynamicAlias()
        {
            var results = FieldAliasWithoutExplicitTypeConditionTests.Lint(
                ifCondition: @"{ ""field"": ""[parameters('aliasName')]"", ""equals"": ""enabled"" }");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_EmptyMetadata()
        {
            var results = FieldAliasWithoutExplicitTypeConditionTests.Lint(
                ifCondition: $@"{{ ""field"": ""{EmptyMetadataAlias}"", ""equals"": ""enabled"" }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_BlankResourceTypes()
        {
            var results = FieldAliasWithoutExplicitTypeConditionTests.Lint(
                ifCondition: $@"{{ ""field"": ""{BlankResourceTypeAlias}"", ""equals"": ""enabled"" }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_FieldAliasWithoutExplicitTypeCondition_RealStorageAlias()
        {
            var results = FieldAliasWithoutExplicitTypeConditionTests.Lint(
                ifCondition: @"{ ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"", ""equals"": true }",
                metadata: FieldAliasWithoutExplicitTypeConditionTests.RealTypeMetadata);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "field-alias-without-explicit-type-condition",
                Title: "Field Alias Without Explicit Type Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 11,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: "The field aliases resolve to resource types: 'Microsoft.Storage/storageAccounts' without an explicit 'type' equals or in condition. Add an explicit condition to make the policy's target resource types clear.");

            results.Should().ContainEquivalentOf(output);
        }

        private static void AssertSingleFinding(string ifCondition, string resourceTypes)
        {
            var results = FieldAliasWithoutExplicitTypeConditionTests.Lint(ifCondition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "field-alias-without-explicit-type-condition",
                Title: "Field Alias Without Explicit Type Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 11,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: $"The field aliases resolve to resource types: '{resourceTypes}' without an explicit 'type' equals or in condition. Add an explicit condition to make the policy's target resource types clear.");

            results.Should().ContainEquivalentOf(output);
        }

        private static LinterOutput[] Lint(string ifCondition)
        {
            return FieldAliasWithoutExplicitTypeConditionTests.Lint(
                ifCondition: ifCondition,
                metadata: FieldAliasWithoutExplicitTypeConditionTests.TypeMetadata);
        }

        private static LinterOutput[] Lint(string ifCondition, ITypeMetadata metadata)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasWithoutExplicitTypeCondition(),
                },
                metadata: metadata);

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""mode"": ""Indexed"",
                    ""parameters"": {{
                      ""targetType"": {{ ""type"": ""String"" }},
                      ""targetTypes"": {{ ""type"": ""Array"" }},
                      ""aliasName"": {{ ""type"": ""String"" }}
                    }},
                    ""policyRule"": {{
                      ""if"": {ifCondition},
                      ""then"": {{
                        ""effect"": ""audit""
                      }}
                    }}
                  }}
                }}";

            return linter.Lint(policyDefinition);
        }

        private sealed class TestTypeMetadata : ITypeMetadata
        {
            private readonly Dictionary<string, ResourcePropertyMetadata[]> aliases =
                new(StringComparer.OrdinalIgnoreCase)
                {
                    [StorageAlias] = new[]
                    {
                        TestTypeMetadata.CreateMetadata("Contoso.Storage/accounts"),
                        TestTypeMetadata.CreateMetadata(" "),
                    },
                    [OtherStorageAlias] = new[]
                    {
                        TestTypeMetadata.CreateMetadata("contoso.storage/accounts"),
                    },
                    [MultipleTypesAlias] = new[]
                    {
                        TestTypeMetadata.CreateMetadata("Contoso.Storage/accounts"),
                        TestTypeMetadata.CreateMetadata("Contoso.Compute/virtualMachines"),
                        TestTypeMetadata.CreateMetadata("contoso.compute/virtualMachines"),
                    },
                    [FieldFunctionAlias] = new[]
                    {
                        TestTypeMetadata.CreateMetadata("Contoso.Network/virtualNetworks"),
                    },
                    [CountArrayAlias] = Array.Empty<ResourcePropertyMetadata>(),
                    [CurrentAlias] = new[]
                    {
                        TestTypeMetadata.CreateMetadata("Contoso.Storage/accounts"),
                    },
                    [EmptyMetadataAlias] = Array.Empty<ResourcePropertyMetadata>(),
                    [BlankResourceTypeAlias] = new[]
                    {
                        TestTypeMetadata.CreateMetadata(string.Empty),
                        TestTypeMetadata.CreateMetadata("  "),
                    },
                };

            public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
            {
                if (aliasName != null && this.aliases.TryGetValue(aliasName, out var metadata))
                {
                    result = metadata;
                    return true;
                }

                result = Array.Empty<ResourcePropertyMetadata>();
                return false;
            }

            private static ResourcePropertyMetadata CreateMetadata(string resourceType)
            {
                return new ResourcePropertyMetadata
                {
                    ResourceType = resourceType,
                };
            }
        }
    }
}
