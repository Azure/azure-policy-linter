// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Xunit;

    public class PolicyExpressionTests
    {
        [Fact]
        public void PolicyExpression_FindAncestorAndIsInExistenceCondition()
        {
            var policy = @"{
                'properties': {
                    'policyRule': {
                        'if': { 'field': 'name', 'equals': 'a' },
                        'then': {
                            'effect': 'auditIfNotExists',
                            'details': {
                                'type': 'Contoso.One/items',
                                'name': '[field(\'name\')]',
                                'existenceCondition': { 'field': 'name', 'equals': '[field(\'name\')]' }
                            }
                        }
                    }
                }
            }";
            var policyRule = new PolicyDefinition(
                policyDefinition: policy.FromJson<PolicyDefinitionObject>(settings: PolicySerializerSettings.Settings),
                typeMetadata: new MockTypeMetadata()).Properties.PolicyRule;
            var details = policyRule.Then.Details.IfNotExists;

            var existenceCondition = (LeafCondition)details.ExistenceCondition;
            existenceCondition.IsInExistenceCondition().Should().BeTrue();
            existenceCondition.Operator.FindAncestor<LeafCondition>().Should().BeSameAs(existenceCondition);
            existenceCondition.Operator.IsInExistenceCondition().Should().BeTrue();
            existenceCondition.Field.FieldAccessorReference.IsInExistenceCondition().Should().BeTrue();
            details.Name.IsInExistenceCondition().Should().BeFalse();
            details.Name.FindAncestor<EffectDetails>().Should().BeSameAs(policyRule.Then.Details);

            var ifCondition = (LeafCondition)policyRule.If.Condition;
            ifCondition.IsInExistenceCondition().Should().BeFalse();
            ifCondition.Operator.FindAncestor<IfCondition>().Should().BeSameAs(policyRule.If);
            ifCondition.Operator.FindAncestor<EffectDetails>().Should().BeNull();
        }
    }
}
