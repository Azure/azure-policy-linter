namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json.Linq;
    using Xunit;

    public class PropertyTests
    {
        [Theory]
        [InlineData("\"[parameters('P')]\"", true)]
        [InlineData("\"[concat(parameters('p'), 'suffix')]\"", false)]
        [InlineData("\"[parameters('p').name]\"", false)]
        [InlineData("[\"[parameters('p')]\"]", false)]
        [InlineData("\"[parameters('missing')]\"", false)]
        [InlineData("'literal'", false)]
        public void Property_SimpleStringParameterValues(string value, bool expected)
        {
            var policy = PropertyTests.CreatePolicy(value: value);
            var property = ((LeafCondition)policy.Properties.PolicyRule.If.Condition).Operator;
            var context = new LinterContext(resourceTypeMetadata: new MockTypeMetadata(), parameters: policy.Properties.Parameters);

            property.HasSimpleParameterizedValue(
                context: context, parameterName: out var name, allowedValues: out var allowed, defaultValue: out var defaultValue)
                .Should().Be(expected);

            if (expected)
            {
                name.Should().Be("P");
                allowed.Should().Equal("first", "second");
                defaultValue.Should().Be("first");
            }
            else
            {
                allowed.Should().BeNull();
                defaultValue.Should().BeNull();
            }
        }

        [Fact]
        public void Property_SimpleArrayParameterName()
        {
            var policy = PropertyTests.CreatePolicy(value: "\"[parameters('TYPES')]\"");
            var property = ((LeafCondition)policy.Properties.PolicyRule.If.Condition).Operator;

            property.IsSimpleParameterReference(parameterName: out var name).Should().BeTrue();
            name.Should().Be("TYPES");

            var context = new LinterContext(resourceTypeMetadata: new MockTypeMetadata(), parameters: policy.Properties.Parameters);
            property.HasSimpleParameterizedValue(
                context: context, parameterName: out _, allowedValues: out var allowed, defaultValue: out var defaultValue)
                .Should().BeFalse();
            allowed.Should().BeNull();
            defaultValue.Should().BeNull();
        }

        [Fact]
        public void Property_ParameterNameDoesNotRequireDefinition()
        {
            var policy = PropertyTests.CreatePolicy(value: "\"[parameters('missing')]\"");
            var property = ((LeafCondition)policy.Properties.PolicyRule.If.Condition).Operator;

            property.IsSimpleParameterReference(parameterName: out var name).Should().BeTrue();
            name.Should().Be("missing");

            var context = new LinterContext(resourceTypeMetadata: new MockTypeMetadata());
            property.HasSimpleParameterizedValue(
                context: context, parameterName: out _, allowedValues: out var allowed, defaultValue: out var defaultValue)
                .Should().BeFalse();
            allowed.Should().BeNull();
            defaultValue.Should().BeNull();
        }

        private static PolicyDefinition CreatePolicy(string value)
        {
            var policy = JObject.Parse(json: @"{
                'properties': {
                    'parameters': {
                        'p': { 'type': 'String', 'allowedValues': ['first', 'second'], 'defaultValue': 'first' },
                        'types': { 'type': 'Array', 'allowedValues': ['Contoso.One/items', 'Contoso.Two/items'], 'defaultValue': ['Contoso.One/items'] }
                    },
                    'policyRule': {
                        'if': { 'field': 'type' },
                        'then': { 'effect': 'audit' }
                    }
                }
            }");
            policy["properties"]["policyRule"]["if"]["in"] = JToken.Parse(json: value);
            return new PolicyDefinition(
                policyDefinition: policy.ToString().FromJson<PolicyDefinitionObject>(settings: PolicySerializerSettings.Settings),
                typeMetadata: new MockTypeMetadata());
        }
    }
}
