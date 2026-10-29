namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json.Linq;
    using Xunit;

    public class ThenExpressionTests
    {
        private static readonly OrdinalInsensitiveHashSet Effects = new OrdinalInsensitiveHashSet { "deny", "modify" };

        [Theory]
        [InlineData("deny", true)]
        [InlineData("Modify", true)]
        [InlineData("audit", false)]
        [InlineData("[parameters('allowsDeny')]", true)]
        [InlineData("[parameters('auditOnly')]", false)]
        [InlineData("[parameters('noAllowedValues')]", false)]
        [InlineData("[parameters('missing')]", false)]
        [InlineData("[toLower(parameters('allowsDeny'))]", false)]
        public void ThenExpression_CanHaveEffect(string effect, bool expected)
        {
            var policy = ThenExpressionTests.CreatePolicy(effect: effect);
            var context = new LinterContext(resourceTypeMetadata: new MockTypeMetadata(), parameters: policy.Properties.Parameters);

            policy.Properties.PolicyRule.Then.CanHaveEffect(context: context, effects: ThenExpressionTests.Effects).Should().Be(expected);
        }

        private static PolicyDefinition CreatePolicy(string effect)
        {
            var policy = JObject.Parse(json: @"{
                'properties': {
                    'parameters': {
                        'allowsDeny': { 'type': 'String', 'allowedValues': ['Audit', 'Deny', 'Disabled'] },
                        'auditOnly': { 'type': 'String', 'allowedValues': ['Audit', 'Disabled'] },
                        'noAllowedValues': { 'type': 'String', 'defaultValue': 'Deny' }
                    },
                    'policyRule': {
                        'if': { 'field': 'type', 'equals': 'Contoso.One/items' },
                        'then': {}
                    }
                }
            }");
            policy["properties"]["policyRule"]["then"]["effect"] = effect;
            return new PolicyDefinition(
                policyDefinition: policy.ToString().FromJson<PolicyDefinitionObject>(settings: PolicySerializerSettings.Settings),
                typeMetadata: new MockTypeMetadata());
        }
    }
}
