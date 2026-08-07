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
    /// Tests for the <see cref="ImplicitResourceTypeTargeting"/> rule.
    /// </summary>
    public class ImplicitResourceTypeTargetingTests
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
        public void RuleTests_ImplicitResourceTypeTargeting_OneAlias()
        {
            ImplicitResourceTypeTargetingTests.AssertSingleFinding(
                ifCondition: $@"{{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}",
                resourceTypes: "Contoso.Storage/accounts");
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_MultipleAliasesSameType()
        {
            ImplicitResourceTypeTargetingTests.AssertSingleFinding(
                ifCondition: $@"{{ ""allOf"": [{{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}, {{ ""field"": ""{OtherStorageAlias}"", ""equals"": ""enabled"" }}] }}",
                resourceTypes: "Contoso.Storage/accounts");
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_MultipleTypesAreSortedAndDeduplicated()
        {
            ImplicitResourceTypeTargetingTests.AssertSingleFinding(
                ifCondition: $@"{{ ""allOf"": [{{ ""field"": ""{MultipleTypesAlias}"", ""equals"": ""enabled"" }}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}",
                resourceTypes: "Contoso.Common/resources, Contoso.Storage/accounts");
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_FieldFunctionAlias()
        {
            ImplicitResourceTypeTargetingTests.AssertSingleFinding(
                ifCondition: $@"{{ ""value"": ""[field('{FieldFunctionAlias}')]"", ""equals"": ""enabled"" }}",
                resourceTypes: "Contoso.Network/virtualNetworks");
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_CurrentFunctionAlias()
        {
            ImplicitResourceTypeTargetingTests.AssertSingleFinding(
                ifCondition: $@"{{ ""count"": {{ ""field"": ""{CountArrayAlias}"", ""where"": {{ ""value"": ""[current('{CurrentAlias}')]"", ""equals"": ""enabled"" }} }}, ""greater"": 0 }}",
                resourceTypes: "Contoso.Storage/accounts");
        }

        [Theory]
        [InlineData(@"{ ""field"": ""type"", ""like"": ""Contoso.Storage/*"" }")]
        [InlineData(@"{ ""field"": ""type"", ""notEquals"": ""Contoso.Storage/accounts"" }")]
        [InlineData(@"{ ""field"": ""type"", ""notIn"": [""Contoso.Storage/accounts""] }")]
        [InlineData(@"{ ""field"": ""type"", ""equals"": ""[parameters('targetType')]"" }")]
        [InlineData(@"{ ""field"": ""type"", ""in"": ""[parameters('targetTypes')]"" }")]
        public void RuleTests_ImplicitResourceTypeTargeting_NonPositiveTypeCondition(string typeCondition)
        {
            ImplicitResourceTypeTargetingTests.AssertSingleFinding(
                ifCondition: $@"{{ ""allOf"": [{typeCondition}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}",
                resourceTypes: "Contoso.Storage/accounts");
        }

        [Theory]
        [InlineData(@"{ ""field"": ""type"", ""equals"": ""   "" }")]
        [InlineData(@"{ ""field"": ""type"", ""in"": [] }")]
        [InlineData(@"{ ""field"": ""type"", ""in"": ["""", ""   ""] }")]
        [InlineData(@"{ ""not"": { ""field"": ""type"", ""equals"": ""Contoso.Storage/accounts"" } }")]
        public void RuleTests_ImplicitResourceTypeTargeting_LiteralTypeConditionCountsAsExplicit(string typeCondition)
        {
            var results = ImplicitResourceTypeTargetingTests.Lint(
                ifCondition: $@"{{ ""allOf"": [{typeCondition}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_PositiveEquals()
        {
            var results = ImplicitResourceTypeTargetingTests.Lint(
                ifCondition: $@"{{ ""allOf"": [{{ ""field"": ""TyPe"", ""equals"": ""Contoso.Storage/accounts"" }}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_ValueFieldTypeIsNotAnExplicitTypeCondition()
        {
            ImplicitResourceTypeTargetingTests.AssertSingleFinding(
                ifCondition: $@"{{ ""allOf"": [{{ ""value"": ""[field('type')]"", ""equals"": ""Contoso.Storage/accounts"" }}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}",
                resourceTypes: "Contoso.Storage/accounts");
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_PositiveNonEmptyIn()
        {
            var results = ImplicitResourceTypeTargetingTests.Lint(
                ifCondition: $@"{{ ""allOf"": [{{ ""field"": ""type"", ""in"": ["""", ""Contoso.Storage/accounts""] }}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_DoubleNotPositiveEquals()
        {
            var results = ImplicitResourceTypeTargetingTests.Lint(
                ifCondition: $@"{{ ""allOf"": [{{ ""not"": {{ ""not"": {{ ""field"": ""type"", ""equals"": ""Contoso.Storage/accounts"" }} }} }}, {{ ""field"": ""{StorageAlias}"", ""equals"": ""enabled"" }}] }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_NoAliases()
        {
            var results = ImplicitResourceTypeTargetingTests.Lint(
                ifCondition: @"{ ""field"": ""location"", ""equals"": ""westus"" }");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_UnresolvedDynamicAlias()
        {
            var results = ImplicitResourceTypeTargetingTests.Lint(
                ifCondition: @"{ ""field"": ""[parameters('aliasName')]"", ""equals"": ""enabled"" }");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_EmptyMetadata()
        {
            var results = ImplicitResourceTypeTargetingTests.Lint(
                ifCondition: $@"{{ ""field"": ""{EmptyMetadataAlias}"", ""equals"": ""enabled"" }}");

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_BlankMetadataResourceTypes_UseAliasResourceType()
        {
            ImplicitResourceTypeTargetingTests.AssertSingleFinding(
                ifCondition: $@"{{ ""field"": ""{BlankResourceTypeAlias}"", ""equals"": ""enabled"" }}",
                resourceTypes: "Contoso.Blank/resources");
        }

        [Fact]
        public void RuleTests_ImplicitResourceTypeTargeting_RealStorageAlias()
        {
            var results = ImplicitResourceTypeTargetingTests.Lint(
                ifCondition: @"{ ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"", ""equals"": true }",
                metadata: ImplicitResourceTypeTargetingTests.RealTypeMetadata);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "implicit-resource-type-targeting",
                Title: "Implicit Resource Type Targeting",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 11,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: "The policy targets fields of 'Microsoft.Storage/storageAccounts' without an explicit 'type' condition, leaving the targeted resource types implicit. Add a 'type' condition using 'equals' or 'in'.");

            results.Should().ContainEquivalentOf(output);
        }

        private static void AssertSingleFinding(string ifCondition, string resourceTypes)
        {
            var results = ImplicitResourceTypeTargetingTests.Lint(ifCondition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "implicit-resource-type-targeting",
                Title: "Implicit Resource Type Targeting",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 11,
                LinePosition: 29,
                Path: "properties.policyRule.if",
                Description: $"The policy targets fields of '{resourceTypes}' without an explicit 'type' condition, leaving the targeted resource types implicit. Add a 'type' condition using 'equals' or 'in'.");

            results.Should().ContainEquivalentOf(output);
        }

        private static LinterOutput[] Lint(string ifCondition)
        {
            return ImplicitResourceTypeTargetingTests.Lint(
                ifCondition: ifCondition,
                metadata: ImplicitResourceTypeTargetingTests.TypeMetadata);
        }

        private static LinterOutput[] Lint(string ifCondition, ITypeMetadata metadata)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ImplicitResourceTypeTargeting(),
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
