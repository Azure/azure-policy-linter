// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System.Collections.Generic;
    using System.Linq;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json.Linq;
    using Xunit;

    public class EffectDetailsTests
    {
        [Theory]
        [InlineData("[ { 'field': 'tags.a', 'value': 'b' } ]", EffectDetailsKind.Append)]
        [InlineData("{ 'type': 'Contoso.One/items' }", EffectDetailsKind.IfNotExists)]
        [InlineData("{ 'TYPE': 'Contoso.One/items' }", EffectDetailsKind.IfNotExists)]
        [InlineData("{ 'type': 'Contoso.One/items', 'operations': [] }", EffectDetailsKind.IfNotExists)]
        [InlineData("{ 'operations': [ { 'operation': 'add', 'field': 'tags.a', 'value': 'b' } ] }", EffectDetailsKind.Modify)]
        [InlineData("{ 'actionNames': [ 'delete' ] }", EffectDetailsKind.Action)]
        [InlineData("{}", EffectDetailsKind.Manual)]
        [InlineData("{ 'defaultState': 'Unknown' }", EffectDetailsKind.Manual)]
        public void EffectDetails_KindIsDetectedFromStructure(string details, EffectDetailsKind expectedKind)
        {
            var then = EffectDetailsTests.CreateThen(details: details);

            then.Details.Should().NotBeNull();
            then.Details.Kind.Should().Be(expectedKind);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("'details'")]
        [InlineData("{ 'defaultState': 'Unknown', 'other': 1 }")]
        [InlineData("{ 'type': 'Contoso.One/items', 'existenceCondition': { 'field': 'name' } }")]
        [InlineData("{ 'operations': [ { 'operation': 'add', 'field': [ 'tags.a' ] } ] }")]
        [InlineData("{ 'operations': 'add' }")]
        [InlineData("{ 'type': '[concat(]' }")]
        [InlineData("{ 'type': 'Contoso.One/items', 'existenceCondition': { 'allOf': [ null ] } }")]
        [InlineData("{ 'type': 'Contoso.One/items', 'existenceCondition': { 'count': { 'field': '[parameters(\\'x\\')]' }, 'equals': 0 } }")]
        public void EffectDetails_UnknownOrMalformedDetailsAreNotModeled(string details)
        {
            EffectDetailsTests.CreateThen(details: details).Details.Should().BeNull();
        }

        [Fact]
        public void EffectDetails_IfNotExistsDetails()
        {
            var then = EffectDetailsTests.CreateThen(details: @"{
                'type': 'Microsoft.Sql/servers/databases/transparentDataEncryption',
                'existenceCondition': {
                    'field': 'Microsoft.Sql/transparentDataEncryption.status',
                    'equals': 'Enabled'
                },
                'deployment': {
                    'properties': {
                        'template': {
                            'parameters': { 'fullDbName': { 'type': 'string' } },
                            'resources': [ { 'name': '[parameters(\'fullDbName\')]' } ]
                        },
                        'parameters': {
                            'fullDbName': { 'value': '[field(\'fullName\')]' }
                        }
                    }
                }
            }");

            var details = then.Details;
            details.Path.Should().Be("properties.policyRule.then.details");
            details.Type.Path.Should().Be("properties.policyRule.then.details.type");
            details.Type.LineNumber.Should().Be(11);
            details.Deployment.Should().NotBeNull();

            var existenceCondition = details.ExistenceCondition.Should().BeOfType<LeafCondition>().Subject;
            existenceCondition.Path.Should().Be("properties.policyRule.then.details.existenceCondition");
            existenceCondition.Field.FieldAccessorReference.Identifier.Should().Be("Microsoft.Sql/transparentDataEncryption.status");
            existenceCondition.Field.LineNumber.Should().Be(13);

            details.DeploymentParameters.Path.Should().Be("properties.policyRule.then.details.deployment.properties.parameters");
            details.DeploymentParameters.LineNumber.Should().Be(22);

            // Template expressions are evaluated by ARM, so only the deployment parameter values hold policy references.
            var references = EffectDetailsTests.Collect<Reference>(expression: details);
            references.Select(reference => (reference.Kind, reference.Identifier)).Should().BeEquivalentTo(new[]
            {
                (ReferenceKind.ResourceField, "Microsoft.Sql/transparentDataEncryption.status"),
                (ReferenceKind.ResourceField, "fullName"),
            });
        }

        [Fact]
        public void EffectDetails_ModifyOperations()
        {
            var then = EffectDetailsTests.CreateThen(details: @"{
                'roleDefinitionIds': [ '/providers/Microsoft.Authorization/roleDefinitions/abc' ],
                'operations': [
                    {
                        'condition': '[greaterOrEquals(requestContext().apiVersion, \'2019-04-01\')]',
                        'operation': 'addOrReplace',
                        'field': 'tags[\'env\']',
                        'value': '[parameters(\'env\')]'
                    }
                ]
            }");

            var operation = then.Details.Operations.Should().ContainSingle().Subject;
            operation.Path.Should().Be("properties.policyRule.then.details.operations[0]");
            operation.LineNumber.Should().Be(13);
            operation.Operation.Value.ToString().Should().Be("addOrReplace");
            operation.Field.Path.Should().Be("properties.policyRule.then.details.operations[0].field");
            operation.Field.FieldAccessorReference.Identifier.Should().Be("tags['env']");
            operation.Value.IsSimpleParameterReference(parameterName: out var parameterName).Should().BeTrue();
            parameterName.Should().Be("env");
            operation.Condition.LanguageExpressions.Should().ContainSingle();
            then.Details.RoleDefinitionIds.LineNumber.Should().Be(11);
            EffectDetailsTests.Collect<Property>(expression: then.Details).Should().Contain(new[] { operation.Operation, operation.Field, operation.Value, operation.Condition });
        }

        [Fact]
        public void EffectDetails_AppendEntries()
        {
            var then = EffectDetailsTests.CreateThen(details: @"[
                { 'field': 'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]', 'value': { 'value': '40.40.40.40', 'action': 'Allow' } },
                { 'field': 'tags.a', 'value': 'b' }
            ]");

            then.Details.Operations.Should().HaveCount(2);

            var entry = then.Details.Operations[1];
            entry.Path.Should().Be("properties.policyRule.then.details[1]");
            entry.LineNumber.Should().Be(12);
            entry.Operation.Should().BeNull();
            entry.Field.FieldAccessorReference.Identifier.Should().Be("tags.a");
            then.Details.Type.Should().BeNull();
        }

        [Fact]
        public void EffectDetails_VisitedWithThenExpression()
        {
            var then = EffectDetailsTests.CreateThen(details: "{ 'actionNames': [ 'delete' ], 'cascadeBehaviors': { 'resourceGroup': '[parameters(\\'behavior\\')]' } }");

            var properties = EffectDetailsTests.Collect<Property>(expression: then);

            properties.Select(property => property.Path).Should().BeEquivalentTo(new[]
            {
                "properties.policyRule.then.effect",
                "properties.policyRule.then.details.actionNames",
                "properties.policyRule.then.details.cascadeBehaviors",
            });
        }

        [Fact]
        public void EffectDetails_IsInExistenceCondition()
        {
            var then = EffectDetailsTests.CreateThen(details: @"{
                'type': 'Contoso.One/items',
                'name': '[field(\'name\')]',
                'existenceCondition': { 'field': 'name', 'equals': '[field(\'name\')]' }
            }");

            var existenceCondition = (LeafCondition)then.Details.ExistenceCondition;
            existenceCondition.IsInExistenceCondition().Should().BeTrue();
            existenceCondition.Operator.FindAncestor<LeafCondition>().Should().BeSameAs(existenceCondition);
            existenceCondition.Operator.IsInExistenceCondition().Should().BeTrue();
            existenceCondition.Field.FieldAccessorReference.IsInExistenceCondition().Should().BeTrue();
            then.Details.Name.IsInExistenceCondition().Should().BeFalse();

            var ifCondition = (LeafCondition)((PolicyRule)then.Parent).If.Condition;
            ifCondition.IsInExistenceCondition().Should().BeFalse();
            ifCondition.Operator.FindAncestor<IfCondition>().Should().NotBeNull();
        }

        private static ThenExpression CreateThen(string details)
        {
            var policy = JObject.Parse(json: @"{
                'properties': {
                    'policyRule': {
                        'if': { 'field': 'type', 'equals': 'Contoso.One/items' },
                        'then': {
                            'effect': '[parameters(\'effect\')]',
                            'details': null
                        }
                    }
                }
            }");

            var policyJson = policy.ToString().Replace("\"details\": null", $"\"details\": {details ?? "null"}");
            return new PolicyDefinition(
                policyDefinition: policyJson.FromJson<PolicyDefinitionObject>(settings: PolicySerializerSettings.Settings),
                typeMetadata: new MockTypeMetadata()).Properties.PolicyRule.Then;
        }

        private static T[] Collect<T>(PolicyExpression expression) where T : PolicyExpression
        {
            var results = new List<T>();
            expression.Visit(visitor: new PolicyExpressionVisitor { Visit = node => { if (node is T match) { results.Add(match); } } });
            return results.ToArray();
        }
    }
}
