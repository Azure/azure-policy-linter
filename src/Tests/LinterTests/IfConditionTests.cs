// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json.Linq;
    using Xunit;

    public class IfConditionTests
    {
        [Theory]
        [InlineData("{ 'field': 'type', 'equals': 'Contoso.Compute/widgets' }", new[] { "Contoso.Compute/widgets" })]
        [InlineData("{ 'field': 'TYPE', 'EQUALS': 'Contoso.Compute/widgets/children' }", new[] { "Contoso.Compute/widgets/children" })]
        [InlineData("{ 'field': 'type', 'in': ['Contoso.Compute/widgets', 'contoso.compute/WIDGETS', 'Contoso.Storage/accounts'] }",
            new[] { "Contoso.Compute/widgets", "Contoso.Storage/accounts" })]
        [InlineData("{ 'anyOf': [{ 'field': 'type', 'equals': 'Contoso.Compute/widgets' }, { 'allOf': [{ 'field': 'type', 'equals': 'Contoso.Storage/accounts' }] }] }",
            new[] { "Contoso.Compute/widgets", "Contoso.Storage/accounts" })]
        [InlineData("{ 'not': { 'not': { 'field': 'type', 'equals': 'Contoso.Compute/widgets' } } }", new[] { "Contoso.Compute/widgets" })]
        [InlineData("{ 'field': 'type', 'in': ['invalid', '', null, 42, 'Contoso.Compute/widgets'] }", new[] { "Contoso.Compute/widgets" })]
        public void IfCondition_ExtractsLiteralResourceTypes(string condition, string[] expected)
        {
            var policy = IfConditionTests.CreatePolicy(condition: condition);

            policy.Properties.PolicyRule.If.ReferencedResourceTypes.Should().BeEquivalentTo(expected);
        }

        [Theory]
        [InlineData("{ 'field': 'type', 'notEquals': 'Contoso.Compute/widgets' }")]
        [InlineData("{ 'field': 'type', 'notIn': ['Contoso.Compute/widgets'] }")]
        [InlineData("{ 'not': { 'field': 'type', 'equals': 'Contoso.Compute/widgets' } }")]
        [InlineData("{ 'not': { 'field': 'type', 'in': ['Contoso.Compute/widgets'] } }")]
        [InlineData("{ 'field': 'type', 'like': 'Contoso.Compute/*' }")]
        [InlineData("{ 'field': 'name', 'equals': 'Contoso.Compute/widgets' }")]
        [InlineData("{ 'value': 'Contoso.Compute/widgets', 'equals': 'Contoso.Storage/accounts' }")]
        [InlineData("{ 'field': 'type', 'in': [] }")]
        [InlineData("{ 'field': 'type', 'in': 'Contoso.Compute/widgets' }")]
        [InlineData("{ 'field': 'type', 'equals': 'not-a-resource-type' }")]
        [InlineData("{ 'field': 'type', 'equals': 'Contoso/widgets' }")]
        [InlineData("{ 'field': 'Unknown.Provider/widgets/name', 'exists': true }")]
        public void IfCondition_ExtractsNoResourceTypes(string condition)
        {
            var policy = IfConditionTests.CreatePolicy(condition: condition);

            policy.Properties.PolicyRule.If.ReferencedResourceTypes.Should().BeEmpty();
        }

        [Theory]
        [InlineData("String", "equals", "'Contoso.Compute/widgets'", null, new[] { "Contoso.Compute/widgets" })]
        [InlineData("String", "equals", "'Contoso.Other/ignored'", "['Contoso.Compute/widgets', 'Contoso.Storage/accounts']",
            new[] { "Contoso.Compute/widgets", "Contoso.Storage/accounts" })]
        [InlineData("Array", "in", "['Contoso.Compute/widgets', 'Contoso.Storage/accounts']", null,
            new[] { "Contoso.Compute/widgets", "Contoso.Storage/accounts" })]
        [InlineData("Array", "in", null, "['Contoso.Compute/widgets', 'Contoso.Storage/accounts']",
            new[] { "Contoso.Compute/widgets", "Contoso.Storage/accounts" })]
        [InlineData("Array", "in", "['Contoso.Other/ignored']", "['Contoso.Compute/widgets']",
            new[] { "Contoso.Compute/widgets" })]
        [InlineData("string", "equals", null, "['Contoso.Compute/widgets', 'contoso.compute/WIDGETS']",
            new[] { "Contoso.Compute/widgets" })]
        public void IfCondition_ExtractsSimpleParameterValues(
            string parameterType, string conditionOperator, string defaultValue, string allowedValues, string[] expected)
        {
            var parameter = new JObject { ["type"] = parameterType };
            if (defaultValue != null)
            {
                parameter["defaultValue"] = JToken.Parse(json: defaultValue);
            }
            if (allowedValues != null)
            {
                parameter["allowedValues"] = JToken.Parse(json: allowedValues);
            }
            var parameters = new JObject { ["resourceTypes"] = parameter };
            var condition = new JObject { ["field"] = "type", [conditionOperator] = "[parameters('RESOURCETYPES')]" };
            var policy = IfConditionTests.CreatePolicy(condition: condition.ToString(), parameters: parameters.ToString());

            policy.Properties.PolicyRule.If.ReferencedResourceTypes.Should().BeEquivalentTo(expected);
        }

        [Theory]
        [InlineData("{ 'resourceTypes': { 'type': 'String' } }")]
        [InlineData("{ 'resourceTypes': { 'type': 'String', 'allowedValues': [], 'defaultValue': 'Contoso.Compute/widgets' } }")]
        [InlineData("{ 'resourceTypes': { 'type': 'Object', 'defaultValue': { 'type': 'Contoso.Compute/widgets' } } }")]
        [InlineData("{ 'resourceTypes': { 'type': 'String', 'defaultValue': 'not-a-type' } }")]
        [InlineData("{}")]
        [InlineData(null)]
        public void IfCondition_UnavailableParameterValuesAreIgnored(string parameters)
        {
            var policy = IfConditionTests.CreatePolicy(
                condition: @"{ 'field': 'type', 'equals': ""[parameters('resourceTypes')]"" }",
                parameters: parameters);

            policy.Properties.PolicyRule.If.ReferencedResourceTypes.Should().BeEmpty();
        }

        [Theory]
        [InlineData(@"{ 'field': 'type', 'equals': ""[concat(parameters('resourceTypes'), '/children')]"" }")]
        [InlineData(@"{ 'field': 'type', 'equals': ""[parameters('resourceTypes').name]"" }")]
        [InlineData(@"{ 'field': 'type', 'in': ['Contoso.Storage/accounts', ""[parameters('resourceTypes')]""] }")]
        [InlineData(@"{ 'not': { 'field': 'type', 'equals': ""[parameters('resourceTypes')]"" } }")]
        public void IfCondition_DoesNotEvaluateOtherParameterExpressions(string condition)
        {
            var policy = IfConditionTests.CreatePolicy(
                condition: condition,
                parameters: "{ 'resourceTypes': { 'type': 'String', 'defaultValue': 'Contoso.Compute/widgets' } }");

            policy.Properties.PolicyRule.If.ReferencedResourceTypes.Should().BeEmpty();
        }

        [Theory]
        [InlineData("{ 'field': 'Contoso.Provider/widgets/name', 'exists': true }")]
        [InlineData(@"{ 'value': ""[field('Contoso.Provider/widgets/name')]"", 'equals': 'example' }")]
        [InlineData("{ 'not': { 'field': 'Contoso.Provider/widgets/name', 'exists': true } }")]
        [InlineData("{ 'allOf': [{ 'field': 'type', 'equals': 'Contoso.Compute/widgets' }, { 'field': 'Contoso.Provider/widgets/name', 'exists': true }] }")]
        public void IfCondition_IncludesDistinctTypesFromResolvedAliases(string condition)
        {
            var policy = IfConditionTests.CreatePolicy(condition: condition, metadata: new AliasMetadata());

            policy.Properties.PolicyRule.If.ReferencedResourceTypes.Should().BeEquivalentTo(
                "Contoso.Compute/widgets", "Contoso.Storage/accounts");
        }

        [Fact]
        public void IfCondition_ResourceTypesAreComputedOnFirstAccessAndCached()
        {
            var policy = IfConditionTests.CreatePolicy(
                condition: @"{ 'field': 'type', 'equals': ""[parameters('resourceTypes')]"" }",
                parameters: "{ 'resourceTypes': { 'type': 'String', 'defaultValue': 'Contoso.Compute/widgets' } }");
            var parameter = policy.Properties.Parameters["resourceTypes"];
            parameter.DefaultValue = new JValue(value: "Contoso.Storage/accounts");

            var condition = policy.Properties.PolicyRule.If;
            var resourceTypes = condition.ReferencedResourceTypes;
            resourceTypes.Should().Equal("Contoso.Storage/accounts");

            parameter.DefaultValue = new JValue(value: "Contoso.Other/ignored");
            condition.ReferencedResourceTypes.Equals(resourceTypes).Should().BeTrue();
            condition.ReferencedResourceTypes.Should().Equal("Contoso.Storage/accounts");
        }

        private static PolicyDefinition CreatePolicy(string condition, string parameters = null, ITypeMetadata metadata = null)
        {
            var policy = JObject.Parse(json: "{ 'properties': { 'policyRule': { 'then': { 'effect': 'audit' } } } }");
            policy["properties"]["policyRule"]["if"] = JToken.Parse(json: condition);
            if (parameters != null)
            {
                policy["properties"]["parameters"] = JToken.Parse(json: parameters);
            }
            return new PolicyDefinition(
                policyDefinition: policy.ToString().FromJson<PolicyDefinitionObject>(settings: PolicySerializerSettings.Settings),
                typeMetadata: metadata ?? new MockTypeMetadata());
        }

        private sealed class AliasMetadata : ITypeMetadata
        {
            public bool TryGetResourceTypeCapabilities(string resourceType, out ResourceTypeCapabilities result)
            {
                result = ResourceTypeCapabilities.None;
                return false;
            }

            public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
            {
                result = Array.Empty<ResourcePropertyMetadata>();
                if (!string.Equals(a: aliasName, b: "Contoso.Provider/widgets/name", comparisonType: StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
                result = new[]
                {
                    new ResourcePropertyMetadata { ResourceType = "Contoso.Compute/widgets" },
                    new ResourcePropertyMetadata { ResourceType = "contoso.compute/WIDGETS" },
                    new ResourcePropertyMetadata { ResourceType = "Contoso.Storage/accounts" },
                };
                return true;
            }
        }
    }
}
