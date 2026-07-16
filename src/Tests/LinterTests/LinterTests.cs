// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;

    using Newtonsoft.Json.Linq;
    using Xunit;

    /// <summary>
    /// Tests for the core linter functionality.
    /// </summary>
    public class LinterTests
    {
        [Fact]
        public void LinterTests_PolicyDefinitionRuleIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            var testRule = new TestPolicyDefinitionLinterRule(descriptionFormat: "Test rule was invoked")
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    return new[] { rule.CreateError(expression) };
                }
            };
            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);


            var result = linter.Lint(@"{ 'properties': { 'mode': 'Indexed', 'policyRule': { 'if': { 'value': 1, 'equals': 1 }, 'then': { 'effect': 'deny' } } } }");
            result.Should().ContainSingle()
                .Which.Description.Should().Be("Test rule was invoked");
        }

        [Fact]
        public void LinterTests_LeafConditionRuleIsInvoked_FieldExpression()
        {
            var mockMetadata = new MockTypeMetadata();
            var testRule = new TestLeafConditionLinterRule(descriptionFormat: "Test rule was invoked")
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    context.Should().NotBeNull();
                    context.ResourceTypeMetadata.Should().Be(mockMetadata);
                    return new[] { rule.CreateError(expression: expression) };
                }
            };
            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var result = linter.Lint(@"{ 'properties': { 'mode': 'Indexed', 'policyRule': { 'if': { 'field': 'name', 'equals': 'whatever' }, 'then': { 'effect': 'deny' } } } }");
            result.Should().ContainSingle()
                .Which.Description.Should().Be("Test rule was invoked");
        }

        [Fact]
        public void LinterTests_LeafConditionRuleIsInvoked_ValueExpression()
        {
            var mockMetadata = new MockTypeMetadata();
            var testRule = new TestLeafConditionLinterRule(descriptionFormat: "Test rule was invoked")
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    context.Should().NotBeNull();
                    context.ResourceTypeMetadata.Should().Be(mockMetadata);
                    return new[] { rule.CreateError(expression) };
                }
            };
            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var result = linter.Lint(@"{ 'properties': { 'mode': 'Indexed', 'policyRule': { 'if': { 'value': 'name', 'equals': 'whatever' }, 'then': { 'effect': 'deny' } } } }");
            result.Should().ContainSingle()
                .Which.Description.Should().Be("Test rule was invoked");
        }

        [Fact]
        public void LinterTests_LeafConditionRuleIsNotInvokedIfPolicyRuleCannotBeParsed()
        {
            var mockMetadata = new MockTypeMetadata();
            var testRule = new TestLeafConditionLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    context.Should().NotBeNull();
                    context.ResourceTypeMetadata.Should().Be(mockMetadata);
                    return new[] { rule.CreateError(expression, "Test rule was invoked") };
                }
            };
            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var result = linter.Lint("{ 'properties': { 'policyRule': 'not an object' } }");

            // Ensure that the test rule output is not present
            result.Should().NotContain(output => output.Description == "Test rule was invoked");
        }

        [Fact]
        public void LinterTests_QuantifierAndLeafConditionRulesAreInvoked()
        {
            var invokedRules = new List<string>();
            var mockMetadata = new MockTypeMetadata();
            var leafConditionRule = new TestLeafConditionLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    context.Should().NotBeNull();
                    context.ResourceTypeMetadata.Should().Be(mockMetadata);
                    invokedRules.Add($"Leaf rule was invoked on {expression.Path}");
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var quantifierRule = new TestQuantifierLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    context.Should().NotBeNull();
                    context.ResourceTypeMetadata.Should().Be(mockMetadata);
                    invokedRules.Add($"Quantifier rule was invoked on path: {expression.Path}");
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new ILinterRule[] { leafConditionRule, quantifierRule }, mockMetadata);

            var complexPolicy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'policyRule': {
                        'if': {
                            'allOf': [
                                {
                                    'anyOf': [
                                        {
                                            'not': {
                                                'field': 'location',
                                                'equals': 'eastus'
                                            }
                                        },
                                        {
                                            'value': 'name',
                                            'equals': 'test'
                                        }
                                    ]
                                },
                                {
                                    'field': 'type',
                                    'equals': 'Microsoft.Compute/virtualMachines'
                                },
                                {
                                    'count': {
                                        'field': 'someArray[*]',
                                        'where': {
                                            'allOf': [
                                                {
                                                    'field': 'name',
                                                    'equals': 'test'
                                                },
                                                {
                                                    'field': 'location',
                                                    'equals': 'eastus'
                                                }
                                            ]
                                        }
                                    },
                                    'equals': 1
                                },
                                {
                                    'count': {
                                        'value': [],
                                        'where': {
                                            'allOf': [
                                                {
                                                    'field': 'name',
                                                    'equals': 'test'
                                                },
                                                {
                                                    'value': 1,
                                                    'equals': 2
                                                }
                                            ]
                                        }
                                    },
                                    'equals': 1
                                }
                            ]
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(complexPolicy);
            result.Should().BeEmpty();

            invokedRules.Should().BeEquivalentTo(
                "Quantifier rule was invoked on path: properties.policyRule.if.allOf",
                "Quantifier rule was invoked on path: properties.policyRule.if.allOf[0].anyOf",
                "Quantifier rule was invoked on path: properties.policyRule.if.allOf[0].anyOf[0].not",
                "Leaf rule was invoked on properties.policyRule.if.allOf[0].anyOf[0].not",
                "Leaf rule was invoked on properties.policyRule.if.allOf[0].anyOf[1]",
                "Leaf rule was invoked on properties.policyRule.if.allOf[1]",
                "Leaf rule was invoked on properties.policyRule.if.allOf[2]",
                "Quantifier rule was invoked on path: properties.policyRule.if.allOf[2].count.where.allOf",
                "Leaf rule was invoked on properties.policyRule.if.allOf[2].count.where.allOf[0]",
                "Leaf rule was invoked on properties.policyRule.if.allOf[2].count.where.allOf[1]",
                "Leaf rule was invoked on properties.policyRule.if.allOf[3]",
                "Quantifier rule was invoked on path: properties.policyRule.if.allOf[3].count.where.allOf",
                "Leaf rule was invoked on properties.policyRule.if.allOf[3].count.where.allOf[0]",
                "Leaf rule was invoked on properties.policyRule.if.allOf[3].count.where.allOf[1]");
        }

        [Fact]
        public void LinterTests_PropertyRuleIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            var invokedRules = new List<string>();
            var testRule = new TestPropertyLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    invokedRules.Add($"Property rule was invoked on '{expression.Name}' with value '{expression.Value}'");
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'policyRule': {
                        'if': {
                            'allOf': [
                                { 'field': 'name', 'equals': 'something' },
                                { 'value': 1, 'equals': 2 }
                            ]
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);

            result.Should().BeEmpty();
            invokedRules.Should().BeEquivalentTo(
                "Property rule was invoked on 'mode' with value 'Indexed'",
                "Property rule was invoked on 'field' with value 'name'",
                "Property rule was invoked on 'equals' with value 'something'",
                "Property rule was invoked on 'value' with value '1'",
                "Property rule was invoked on 'equals' with value '2'",
                "Property rule was invoked on 'effect' with value 'deny'");
        }

        [Fact]
        public void LinterTests_CountRuleIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            Count invokedCountExpression = null;
            var testRule = new TestCountLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    invokedCountExpression = expression;
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'policyRule': {
                        'if': {
                            'count': {
                                'value': [],
                                'name': 'whatever',
                                'where': {
                                    'value': 1,
                                    'equals': 2
                                }
                            },
                            'equals': 1
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);

            result.Should().BeEmpty();
            invokedCountExpression.Should().NotBeNull();
            invokedCountExpression.EnumeratedArray.Should().NotBeNull();
            invokedCountExpression.EnumeratedArray.Name.Should().Be("value");
            invokedCountExpression.Name.Should().NotBeNull();
            invokedCountExpression.Where.Should().NotBeNull();
        }

        [Fact]
        public void LinterTests_ReferenceRuleIsInvoked_LiteralFieldReferenceIfFieldAccessor()
        {
            var mockMetadata = new MockTypeMetadata();
            var references = new List<Reference>();
            var testRule = new TestReferenceLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    references.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'policyRule': {
                        'if': {
                            'allOf': [
                                { 'field': 'name', 'equals': 'something' },
                                { 'value': 1, 'equals': 2 }
                            ]
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);
            result.Should().BeEmpty();

            references.Should().HaveCount(1);

            references[0].IsResolved.Should().BeTrue();
            references[0].Identifier.Should().Be("name");
            references[0].PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "field" });
            references[0].Kind.Should().Be(ReferenceKind.ResourceField);
            references[0].Parent.Should().BeOfType<Property>().Subject.Name.Should().Be("field");
            references[0].ResolutionDependencies.Should().BeEmpty();
            references[0].PropertySelectionPath.Should().BeNull();
            references[0].ReferencedCountExpressionScope.Should().BeNull();
        }

        [Fact]
        public void LinterTests_ReferenceRuleIsInvoked_ParameterReferenceInFieldAccessor()
        {
            var mockMetadata = new MockTypeMetadata();
            var references = new List<Reference>();
            var testRule = new TestReferenceLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    references.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'policyRule': {
                        'if': {
                            'allOf': [
                                { 'field': ""[parameters('paramA')[parameters(concat('param','B'))]]"", 'equals': 'something' },
                                { 'value': 1, 'equals': 2 }
                            ]
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);
            result.Should().BeEmpty();

            references.Should().HaveCount(3);

            // The first reference should be the unresolved field reference, pointing to nested references in the function parameters & property selection path
            var reference = references[0];
            reference.IsResolved.Should().BeFalse();
            reference.Identifier.Should().BeEmpty();
            reference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "field" });
            reference.Kind.Should().Be(ReferenceKind.ResourceField);
            references[0].Parent.Should().BeOfType<Property>().Subject.Name.Should().Be("field");
            reference.ResolutionDependencies.Should().HaveCount(1);
            reference.PropertySelectionPath.Should().BeNull();

            var paramAReference = reference.ResolutionDependencies[0];
            paramAReference.IsResolved.Should().BeTrue();
            paramAReference.Identifier.Should().Be("paramA");
            paramAReference.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            paramAReference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "field" });
            paramAReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("field");

            paramAReference.ResolutionDependencies.Should().BeEmpty();

            var propertySelectionPath = paramAReference.PropertySelectionPath;
            propertySelectionPath.Should().NotBeNull();
            propertySelectionPath.Path.Should().BeEmpty();
            propertySelectionPath.IsResolved.Should().BeFalse();
            propertySelectionPath.ResolutionDependencies.Should().HaveCount(1);
            propertySelectionPath.ResolutionDependencies[0].Kind.Should().Be(ReferenceKind.PolicyParameterName);
            propertySelectionPath.ResolutionDependencies[0].IsResolved.Should().BeTrue();
            propertySelectionPath.ResolutionDependencies[0].Identifier.Should().Be("paramB");
            propertySelectionPath.ResolutionDependencies[0].PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "field" });
            propertySelectionPath.ResolutionDependencies[0].Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("field");

            var paramBReference = propertySelectionPath.ResolutionDependencies[0];

            // But... we should also be invoked for these nested references
            references.Should().Contain(paramAReference);
            references.Should().Contain(paramBReference);
        }

        [Fact]
        public void LinterTests_ReferenceRuleIsInvoked_FieldReferenceInFieldAccessor()
        {
            var mockMetadata = new MockTypeMetadata();
            var references = new List<Reference>();
            var testRule = new TestReferenceLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    references.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'policyRule': {
                        'if': {
                            'allOf': [
                                { 'field': ""[field('tags.x')]"", 'equals': 'something' },
                                { 'value': 1, 'equals': 2 }
                            ]
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);
            result.Should().BeEmpty();

            references.Should().HaveCount(2);

            // The first reference should be the unresolved field reference, pointing to the tags.x reference
            var reference = references[0];
            reference.IsResolved.Should().BeFalse();
            reference.Identifier.Should().BeEmpty();
            reference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "field" });
            reference.Kind.Should().Be(ReferenceKind.ResourceField);
            references[0].Parent.Should().BeOfType<Property>().Subject.Name.Should().Be("field");
            reference.ResolutionDependencies.Should().HaveCount(1);
            reference.PropertySelectionPath.Should().BeNull();

            var tagsXReference = reference.ResolutionDependencies[0];
            tagsXReference.IsResolved.Should().BeTrue();
            tagsXReference.Identifier.Should().Be("tags.x");
            tagsXReference.Kind.Should().Be(ReferenceKind.ResourceField);
            tagsXReference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "field" });
            tagsXReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>();
            tagsXReference.ResolutionDependencies.Should().BeEmpty();

            // Ensure that the tags.x reference is included in the references list
            references.Should().Contain(tagsXReference);
        }

        [Fact]
        public void LinterTests_ReferenceRuleIsInvoked_ReferencesInValueAccessor()
        {
            var mockMetadata = new MockTypeMetadata();
            var references = new List<Reference>();
            var testRule = new TestReferenceLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    references.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'policyRule': {
                        'if': {
                            'allOf': [
                                { 'value': ""[field(parameters('paramA')[parameters(concat('param','B'))])]"", 'equals': 'something' },
                                { 'value': 1, 'equals': 2 }
                            ]
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);
            result.Should().BeEmpty();

            references.Should().HaveCount(3);

            // The first reference should be the unresolved value reference, pointing to nested references in the function parameters & property selection path
            var reference = references[0];
            reference.IsResolved.Should().BeFalse();
            reference.Identifier.Should().BeEmpty();
            reference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "value" });
            reference.Kind.Should().Be(ReferenceKind.ResourceField);
            references[0].Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("value");

            reference.ResolutionDependencies.Should().HaveCount(1);
            reference.PropertySelectionPath.Should().BeNull();

            var paramAReference = reference.ResolutionDependencies[0];
            paramAReference.IsResolved.Should().BeTrue();
            paramAReference.Identifier.Should().Be("paramA");
            paramAReference.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            paramAReference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "value" });
            paramAReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("value");

            paramAReference.ResolutionDependencies.Should().BeEmpty();

            var propertySelectionPath = paramAReference.PropertySelectionPath;
            propertySelectionPath.Should().NotBeNull();
            propertySelectionPath.Path.Should().BeEmpty();
            propertySelectionPath.IsResolved.Should().BeFalse();
            propertySelectionPath.ResolutionDependencies.Should().HaveCount(1);
            propertySelectionPath.ResolutionDependencies[0].Kind.Should().Be(ReferenceKind.PolicyParameterName);
            propertySelectionPath.ResolutionDependencies[0].IsResolved.Should().BeTrue();
            propertySelectionPath.ResolutionDependencies[0].Identifier.Should().Be("paramB");
            propertySelectionPath.ResolutionDependencies[0].PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "value" });
            propertySelectionPath.ResolutionDependencies[0].Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("value");

            var paramBReference = propertySelectionPath.ResolutionDependencies[0];

            // But... we should also be invoked for these nested references
            references.Should().Contain(paramAReference);
            references.Should().Contain(paramBReference);
        }

        [Fact]
        public void LinterTests_ReferenceRuleIsInvoked_UnresolvedFieldReferenceInOperator()
        {
            var mockMetadata = new MockTypeMetadata();
            var references = new List<Reference>();
            var testRule = new TestReferenceLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    references.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'policyRule': {
                        'if': {
                            'allOf': [
                                { 'value': 1, 'equals': ""[field(parameters('paramA')[parameters(concat('param','B'))])]"" },
                                { 'value': 1, 'equals': 2 }
                            ]
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);
            result.Should().BeEmpty();

            references.Should().HaveCount(3);

            // The first reference should be the unresolved equals reference, pointing to nested references in the function parameters & property selection path
            var reference = references[0];
            reference.IsResolved.Should().BeFalse();
            reference.Identifier.Should().BeEmpty();
            reference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "equals" });
            reference.Kind.Should().Be(ReferenceKind.ResourceField);
            references[0].Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("equals");
            reference.ResolutionDependencies.Should().HaveCount(1);
            reference.PropertySelectionPath.Should().BeNull();

            var paramAReference = reference.ResolutionDependencies[0];
            paramAReference.IsResolved.Should().BeTrue();
            paramAReference.Identifier.Should().Be("paramA");
            paramAReference.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            paramAReference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "equals" });
            paramAReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("equals");
            paramAReference.ResolutionDependencies.Should().BeEmpty();

            var propertySelectionPath = paramAReference.PropertySelectionPath;
            propertySelectionPath.Should().NotBeNull();
            propertySelectionPath.Path.Should().BeEmpty();
            propertySelectionPath.IsResolved.Should().BeFalse();
            propertySelectionPath.ResolutionDependencies.Should().HaveCount(1);
            propertySelectionPath.ResolutionDependencies[0].Kind.Should().Be(ReferenceKind.PolicyParameterName);
            propertySelectionPath.ResolutionDependencies[0].IsResolved.Should().BeTrue();
            propertySelectionPath.ResolutionDependencies[0].Identifier.Should().Be("paramB");
            propertySelectionPath.ResolutionDependencies[0].PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "equals" });
            propertySelectionPath.ResolutionDependencies[0].Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("equals"); var paramBReference = propertySelectionPath.ResolutionDependencies[0];

            // But... we should also be invoked for these nested references
            references.Should().Contain(paramAReference);
            references.Should().Contain(paramBReference);
        }

        [Fact]
        public void LinterTests_ReferenceRuleIsInvoked_InOperator()
        {
            var mockMetadata = new MockTypeMetadata();
            var references = new List<Reference>();
            var testRule = new TestReferenceLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    references.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'policyRule': {
                        'if': {
                            'allOf': [
                                { 'value': 'something', 'in': [
                                    ""[concat('1','2')]"",
                                    ""[field('tags.x')]"",
                                    ""[field(concat('tags.', 'y'))]"",
                                    ""[parameters('objParam').prop1]"",
                                    ""[resourceGroup().tags.rgTag1]"",
                                    ""[resourceGroup()[concat('na', 'me')]]"",
                                    ""[subscription().tags.subTag1]"",
                                    ""[subscription()[concat('i', 'd')]]"",
                                    ""[requestContext().property1]"",
                                    ""[requestContext()[concat('property', '2')]]""
                                ]},
                                { 'value': 1, 'equals': 2 }
                            ]
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);
            result.Should().BeEmpty();

            references.Should().HaveCount(9);

            // Validate each reference
            var tagsXReference = references.Single(r => r.Identifier == "tags.x" && r.Kind == ReferenceKind.ResourceField);
            tagsXReference.IsResolved.Should().BeTrue();
            tagsXReference.Identifier.Should().Be("tags.x");
            tagsXReference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "in" });
            tagsXReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("in");
            tagsXReference.ResolutionDependencies.Should().BeEmpty();
            tagsXReference.PropertySelectionPath.Should().BeNull();

            var tagsYReference = references.Single(r => r.Identifier == "tags.y" && r.Kind == ReferenceKind.ResourceField);
            tagsYReference.IsResolved.Should().BeTrue();
            tagsYReference.Identifier.Should().Be("tags.y");
            tagsYReference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "in" });
            tagsXReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("in");
            tagsYReference.ResolutionDependencies.Should().BeEmpty();
            tagsYReference.PropertySelectionPath.Should().BeNull();

            var objParamReference = references.Single(r => r.Identifier == "objParam" && r.Kind == ReferenceKind.PolicyParameterName);
            objParamReference.IsResolved.Should().BeTrue();
            objParamReference.Identifier.Should().Be("objParam");
            objParamReference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "in" });
            tagsXReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("in");
            objParamReference.ResolutionDependencies.Should().BeEmpty();
            objParamReference.PropertySelectionPath.Should().NotBeNull();
            objParamReference.PropertySelectionPath.Path.Should().BeEquivalentTo(new[] { "prop1" });

            var rgTag1Reference = references.Single(r => r.Identifier == "resourceGroup" && r.Kind == ReferenceKind.ResourceGroupProperty && r.PropertySelectionPath.Path.SequenceEqual(new[] { "tags", "rgTag1" }));
            rgTag1Reference.IsResolved.Should().BeTrue();
            rgTag1Reference.Identifier.Should().Be("resourceGroup");
            rgTag1Reference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "in" });
            tagsXReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("in");
            rgTag1Reference.ResolutionDependencies.Should().BeEmpty();

            var nameReference = references.Single(r => r.Identifier == "resourceGroup" && r.Kind == ReferenceKind.ResourceGroupProperty && r.PropertySelectionPath.Path.SequenceEqual(new[] { "name" }));
            nameReference.IsResolved.Should().BeTrue();
            nameReference.Identifier.Should().Be("resourceGroup");
            nameReference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "in" });
            tagsXReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("in");
            nameReference.ResolutionDependencies.Should().BeEmpty();

            var subTag1Reference = references.Single(r => r.Identifier == "subscription" && r.Kind == ReferenceKind.SubscriptionProperty && r.PropertySelectionPath.Path.SequenceEqual(new[] { "tags", "subTag1" }));
            subTag1Reference.IsResolved.Should().BeTrue();
            subTag1Reference.Identifier.Should().Be("subscription");
            subTag1Reference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "in" });
            tagsXReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("in");
            subTag1Reference.ResolutionDependencies.Should().BeEmpty();

            var idReference = references.Single(r => r.Identifier == "subscription" && r.Kind == ReferenceKind.SubscriptionProperty && r.PropertySelectionPath.Path.SequenceEqual(new[] { "id" }));
            idReference.IsResolved.Should().BeTrue();
            idReference.Identifier.Should().Be("subscription");
            idReference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "in" });
            tagsXReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("in");
            idReference.ResolutionDependencies.Should().BeEmpty();

            var property1Reference = references.Single(r => r.Identifier == "requestContext" && r.Kind == ReferenceKind.RequestContextProperty && r.PropertySelectionPath.Path.SequenceEqual(new[] { "property1" }));
            property1Reference.IsResolved.Should().BeTrue();
            property1Reference.Identifier.Should().Be("requestContext");
            property1Reference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "in" });
            tagsXReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("in");
            property1Reference.ResolutionDependencies.Should().BeEmpty();

            var property2Reference = references.Single(r => r.Identifier == "requestContext" && r.Kind == ReferenceKind.RequestContextProperty && r.PropertySelectionPath.Path.SequenceEqual(new[] { "property2" }));
            property2Reference.IsResolved.Should().BeTrue();
            property2Reference.Identifier.Should().Be("requestContext");
            property2Reference.PathSegments.Should().BeEquivalentTo(new[] { "properties", "policyRule", "if", "allOf[0]", "in" });
            tagsXReference.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("in");
            property2Reference.ResolutionDependencies.Should().BeEmpty();
        }

        [Fact]
        public void LinterTests_ReferenceRuleIsInvoked_CountExpression()
        {
            var references = new List<Reference>();
            var mockMetadata = new MockTypeMetadata();
            var rule = new TestReferenceLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    references.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { rule }, mockMetadata);

            var policy = @"
            {
              ""properties"": {
                  ""mode"": ""Indexed"",
                  ""policyRule"": {
                      ""if"": {
                          ""count"": {
                            ""field"": ""Microsoft.Test/testResource/array[*]"", // Assume that each array member is an object with properties a,b,c,d, nestedArray
                            ""where"": {
                              ""count"": {
                                ""value"": ""[parameters('arrayParam')]"", // Assume that arrayParam is an array of objects with property a, b
                                ""name"": ""currParam"",
                                ""where"": {
                                  ""anyOf"": [
                                    {
                                      ""field"": ""Microsoft.Test/testResource/array[*].a"",
                                      ""equals"": ""[current('currParam').a]""
                                    },
                                    {
                                      ""value"": ""[first(field('Microsoft.Test/testResource/array[*].b'))]"",
                                      ""equals"": ""[current('Microsoft.Test/testResource/array[*].c')]""
                                    },
                                    {
                                      ""count"": {
                                        ""field"": ""Microsoft.Test/testResource/array[*].nestedArray[*]"", // Assume that each nestedArray member is an object with properties a,b,c
                                        ""where"": {
                                          ""anyOf"": [
                                            {
                                              ""field"": ""Microsoft.Test/testResource/array[*].nestedArray[*].a"",
                                              ""equals"": ""[current('Microsoft.Test/testResource/array[*].nestedArray[*].b')]""
                                            },
                                            {
                                              ""value"": ""[first(field('Microsoft.Test/testResource/array[*].nestedArray[*].c'))]"",
                                              ""equals"": ""1""
                                            }
                                          ]
                                        }
                                      },
                                      ""equals"": ""[add(current('Microsoft.Test/testResource/array[*]'), current('currParam').b)]""
                                    }
                                  ]
                                }
                              },
                              ""greater"": 0
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

            linter.Lint(policy).Should().BeEmpty();
            var referencesByPath = references.ToLookup(keySelector: reference => string.Join('.', reference.Path));
            referencesByPath.Should().HaveCount(11);

            referencesByPath["properties.policyRule.if.count.field"].Should().HaveCount(1);
            referencesByPath["properties.policyRule.if.count.field"].Should().Contain(reference => reference.Kind == ReferenceKind.ResourceField && reference.Identifier == "Microsoft.Test/testResource/array[*]");

            referencesByPath["properties.policyRule.if.count.where.count.value"].Should().HaveCount(1);
            referencesByPath["properties.policyRule.if.count.where.count.value"].Should().Contain(reference => reference.Kind == ReferenceKind.PolicyParameterName && reference.Identifier == "arrayParam");

            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[0].field"].Should().HaveCount(1);
            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[0].field"]
                .Should()
                .Contain(reference =>
                    reference.Kind == ReferenceKind.ResourceField &&
                    reference.Identifier == "Microsoft.Test/testResource/array[*].a" &&
                    reference.ReferencedCountExpressionScope != null &&
                    reference.ReferencedCountExpressionScope.Type == CountScopeType.Field &&
                    reference.ReferencedCountExpressionScope.Identifier == "Microsoft.Test/testResource/array[*]");

            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[0].equals"].Should().HaveCount(1);
            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[0].equals"]
                .Should()
                .Contain(reference =>
                    reference.Kind == ReferenceKind.CurrentArrayMember &&
                    reference.Identifier == "currParam" &&
                    reference.PropertySelectionPath != null &&
                    reference.PropertySelectionPath.IsResolved &&
                    reference.PropertySelectionPath.Path.Length == 1 &&
                    reference.PropertySelectionPath.Path[0] == "a" &&
                    reference.ReferencedCountExpressionScope != null &&
                    reference.ReferencedCountExpressionScope.Type == CountScopeType.Value &&
                    reference.ReferencedCountExpressionScope.Identifier == "currParam");

            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[1].value"].Should().HaveCount(1);
            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[1].value"]
                .Should()
                .Contain(reference =>
                    reference.Kind == ReferenceKind.ResourceField &&
                    reference.Identifier == "Microsoft.Test/testResource/array[*].b" &&
                    reference.ReferencedCountExpressionScope != null &&
                    reference.ReferencedCountExpressionScope.Type == CountScopeType.Field &&
                    reference.ReferencedCountExpressionScope.Identifier == "Microsoft.Test/testResource/array[*]");

            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[1].equals"].Should().HaveCount(1);
            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[1].equals"]
                .Should()
                .Contain(reference =>
                    reference.Kind == ReferenceKind.CurrentArrayMember &&
                    reference.Identifier == "Microsoft.Test/testResource/array[*].c" &&
                    reference.ReferencedCountExpressionScope != null &&
                    reference.ReferencedCountExpressionScope.Type == CountScopeType.Field &&
                    reference.ReferencedCountExpressionScope.Identifier == "Microsoft.Test/testResource/array[*]");

            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].count.field"].Should().HaveCount(1);
            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].count.field"]
                .Should()
                .Contain(reference =>
                    reference.Kind == ReferenceKind.ResourceField &&
                    reference.Identifier == "Microsoft.Test/testResource/array[*].nestedArray[*]" &&
                    reference.ReferencedCountExpressionScope != null &&
                    reference.ReferencedCountExpressionScope.Type == CountScopeType.Field &&
                    reference.ReferencedCountExpressionScope.Identifier == "Microsoft.Test/testResource/array[*]");

            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].equals"].Should().HaveCount(2);
            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].equals"]
                .Should()
                .Contain(reference =>
                    reference.Kind == ReferenceKind.CurrentArrayMember &&
                    reference.Identifier == "Microsoft.Test/testResource/array[*]" &&
                    reference.ReferencedCountExpressionScope != null &&
                    reference.ReferencedCountExpressionScope.Type == CountScopeType.Field &&
                    reference.ReferencedCountExpressionScope.Identifier == "Microsoft.Test/testResource/array[*]");

            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].equals"]
                .Should()
                .Contain(reference =>
                    reference.Kind == ReferenceKind.CurrentArrayMember &&
                    reference.Identifier == "currParam" &&
                    reference.PropertySelectionPath != null &&
                    reference.PropertySelectionPath.IsResolved &&
                    reference.PropertySelectionPath.Path.Length == 1 &&
                    reference.PropertySelectionPath.Path[0] == "b" &&
                    reference.ReferencedCountExpressionScope != null &&
                    reference.ReferencedCountExpressionScope.Type == CountScopeType.Value &&
                    reference.ReferencedCountExpressionScope.Identifier == "currParam");

            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].count.where.anyOf[0].field"].Should().HaveCount(1);
            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].count.where.anyOf[0].field"]
                .Should()
                .Contain(reference =>
                    reference.Kind == ReferenceKind.ResourceField &&
                    reference.Identifier == "Microsoft.Test/testResource/array[*].nestedArray[*].a" &&
                    reference.ReferencedCountExpressionScope != null &&
                    reference.ReferencedCountExpressionScope.Type == CountScopeType.Field &&
                    reference.ReferencedCountExpressionScope.Identifier == "Microsoft.Test/testResource/array[*].nestedArray[*]");

            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].count.where.anyOf[0].equals"].Should().HaveCount(1);
            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].count.where.anyOf[0].equals"]
                .Should()
                .Contain(reference =>
                    reference.Kind == ReferenceKind.CurrentArrayMember &&
                    reference.Identifier == "Microsoft.Test/testResource/array[*].nestedArray[*].b" &&
                    reference.ReferencedCountExpressionScope != null &&
                    reference.ReferencedCountExpressionScope.Type == CountScopeType.Field &&
                    reference.ReferencedCountExpressionScope.Identifier == "Microsoft.Test/testResource/array[*].nestedArray[*]");

            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].count.where.anyOf[1].value"].Should().HaveCount(1);
            referencesByPath["properties.policyRule.if.count.where.count.where.anyOf[2].count.where.anyOf[1].value"]
                .Should()
                .Contain(reference =>
                    reference.Kind == ReferenceKind.ResourceField &&
                    reference.Identifier == "Microsoft.Test/testResource/array[*].nestedArray[*].c" &&
                    reference.ReferencedCountExpressionScope != null &&
                    reference.ReferencedCountExpressionScope.Type == CountScopeType.Field &&
                    reference.ReferencedCountExpressionScope.Identifier == "Microsoft.Test/testResource/array[*].nestedArray[*]");
        }

        [Fact]
        public void LinterTests_LeafConditionRuleAggregationIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            var counter = 0;
            var visited = new List<string>();

            var testRule = new TestLeafConditionLinterRule(descriptionFormat: "Invoke count: {0}")
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    visited.Add($"Test rule was invoked on {expression.Path}");
                    counter++;
                    // If this is the second invocation, emit a warning with the counter
                    if (counter == 2)
                    {
                        visited.Add($"Test rule was invoked {counter} times");
                        return new[] { rule.CreateWarning(null, counter) };
                    }
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var policy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'policyRule': {
                        'if': {
                            'allOf': [
                                { 'field': 'name', 'equals': 'something' },
                                { 'value': 1, 'equals': 2 }
                            ]
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);
            var result = linter.Lint(policy);

            visited.Should().BeEquivalentTo(
                "Test rule was invoked on properties.policyRule.if.allOf[0]",
                "Test rule was invoked on properties.policyRule.if.allOf[1]",
                "Test rule was invoked 2 times");

            result.Should().HaveCount(1);
            result[0].Severity.Should().Be(Severity.Warning);
            result[0].Description.Should().Be("Invoke count: 2");
        }

        [Fact]
        public void LinterTests_ParametersRuleIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            var testRule = new TestParametersLinterRule(descriptionFormat: "Test rule for Parameters was invoked")
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    expression.Name.Should().Be("param1");
                    expression.Type.Should().Be("string");
                    expression.Path.Should().Be("properties.parameters.param1");
                    expression.Metadata.Should().BeOfType<JObject>()
                        .Which["displayName"]!
                        .Value<string>()
                        .Should()
                        .Be("Parameter 1");

                    return new[] { rule.CreateError(expression) };
                }
            };
            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var result = linter.Lint(@"{ 'properties': { 'parameters': { 'param1': { 'type': 'string', 'metadata': { 'displayName': 'Parameter 1' } } }, 'policyRule': { 'if': { 'value': 1, 'equals': 1 }, 'then': { 'effect': 'deny' } } } }");

            result.Should().ContainSingle()
                .Which.Description.Should().Be("Test rule for Parameters was invoked");
        }

        [Fact]
        public void LinterTests_ThenExpressionRuleIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            var testRule = new TestThenExpressionLinterRule(descriptionFormat: "Test rule for ThenExpression was invoked")
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    return new[] { rule.CreateError(expression) };
                }
            };
            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var result = linter.Lint(@"{ 'properties': { 'mode': 'Indexed', 'policyRule': { 'if': { 'value': 1, 'equals': 1 }, 'then': { 'effect': 'deny' } } } }");
            result.Should().ContainSingle()
                .Which.Description.Should().Be("Test rule for ThenExpression was invoked");
        }

        [Fact]
        public void LinterTests_ContextContainsParametersReference()
        {
            var mockMetadata = new MockTypeMetadata();

            var testRule = new TestLeafConditionLinterRule(descriptionFormat: "Test rule was invoked")
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    context.Should().NotBeNull();
                    context.Parameters.Should().NotBeNull();
                    context.Parameters.Should().ContainKey("param1");
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'parameters': { 'param1': { 'type': 'string' } },
                    'policyRule': {
                        'if': { 'field': 'name', 'equals': 'whatever' },
                        'then': { 'effect': 'deny' }
                    }
                }
            }";

            var result = linter.Lint(policy);

            result.Should().BeEmpty();
        }

        [Fact]
        public void LinterTests_VisitAllTemplateLanguageExpressions()
        {
            var languageExpressions = new List<TemplateLanguageExpression>();
            var mockMetadata = new MockTypeMetadata();
            var testRule = new TestTemplateLanguageExpressionLinterRule()
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    languageExpressions.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var policy = @"
            {
                'properties': {
                    'mode': 'Indexed',
                    'parameters': {
                        'effectParam': { 'type': 'string', 'defaultValue': 'deny' },
                        'param': { 'type': 'string' }
                    },
                    'policyRule': {
                        'if': {
                            'allOf': [
                                { 'field': ""[field('tags.x')]"", 'equals': ""[concat('a','b')]"" },
                                { 'value': ""[field(parameters('param'))]"", 'in': [""[field('tags.y')]""] },
                            ]
                        },
                        'then': {
                            'effect': ""[parameters('effectParam')]""
                        }
                    }
                }
            }";

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var result = linter.Lint(policy);

            languageExpressions.Should().HaveCount(5);

            var fieldTagsX = languageExpressions.SingleOrDefault(e => e.Expression == "[field('tags.x')]");
            fieldTagsX.Should().NotBeNull();
            fieldTagsX.References.Should().HaveCount(1);
            fieldTagsX.References[0].Kind.Should().Be(ReferenceKind.ResourceField);
            fieldTagsX.Parent.Should().BeOfType<Property>().Subject.Name.Should().Be("field");

            var concatAB = languageExpressions.SingleOrDefault(e => e.Expression == "[concat('a','b')]");
            concatAB.Should().NotBeNull();
            concatAB.References.Should().BeEmpty();
            concatAB.Parent.Should().BeOfType<Property>().Subject.Name.Should().Be("equals");

            var fieldParam = languageExpressions.SingleOrDefault(e => e.Expression == "[field(parameters('param'))]");
            fieldParam.Should().NotBeNull();
            fieldParam.References.Should().HaveCount(1);
            fieldParam.References[0].Kind.Should().Be(ReferenceKind.ResourceField);
            fieldParam.References[0].ResolutionDependencies.Should().HaveCount(1);
            fieldParam.References[0].ResolutionDependencies[0].Kind.Should().Be(ReferenceKind.PolicyParameterName);
            fieldParam.References[0].ResolutionDependencies[0].Parent.Should().BeOfType<TemplateLanguageExpression>();
            fieldParam.Parent.Should().BeOfType<Property>().Subject.Name.Should().Be("value");

            var fieldTagsY = languageExpressions.SingleOrDefault(e => e.Expression == "[field('tags.y')]");
            fieldTagsY.Should().NotBeNull();
            fieldTagsY.References.Should().HaveCount(1);
            fieldTagsY.References[0].Kind.Should().Be(ReferenceKind.ResourceField);
            fieldTagsY.References[0].Identifier.Should().Be("tags.y");
            fieldTagsY.Parent.Should().BeOfType<Property>().Subject.Name.Should().Be("in");

            var effectParam = languageExpressions.SingleOrDefault(e => e.Expression == "[parameters('effectParam')]");
            effectParam.Should().NotBeNull();
            effectParam.References.Should().HaveCount(1);
            effectParam.References[0].Kind.Should().Be(ReferenceKind.PolicyParameterName);
            effectParam.References[0].Identifier.Should().Be("effectParam");
            effectParam.Parent.Should().BeOfType<Property>().Subject.Name.Should().Be("effect");
        }

        [Fact]
        public void LinterTests_Parameter_TryAsConcreteType_WorksForSupportedTypes()
        {
            var stringParamObj = new ParameterObject
            {
                Type = new GenericObjectProperty<string> { Value = "String" },
                DefaultValue = new GenericObjectProperty<JToken> { Value = JToken.FromObject("b") },
                AllowedValues = new GenericObjectProperty<GenericObjectProperty<JToken>[]>
                {
                    Value = new[]
                    {
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject("a") },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject("b") },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject("c") }
                    }
                }
            };

            var intParamObj = new ParameterObject
            {
                Type = new GenericObjectProperty<string> { Value = "Integer" },
                DefaultValue = new GenericObjectProperty<JToken> { Value = JToken.FromObject(2) },
                AllowedValues = new GenericObjectProperty<GenericObjectProperty<JToken>[]>
                {
                    Value = new[]
                    {
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(1) },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(2) },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(3) }
                    }
                }
            };

            var floatParamObj = new ParameterObject
            {
                Type = new GenericObjectProperty<string> { Value = "Float" },
                DefaultValue = new GenericObjectProperty<JToken> { Value = JToken.FromObject(2.2) },
                AllowedValues = new GenericObjectProperty<GenericObjectProperty<JToken>[]>
                {
                    Value = new[]
                    {
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(1.1) },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(2.2) },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(3.3) }
                    }
                }
            };

            var dateTimeParamObj = new ParameterObject
            {
                Type = new GenericObjectProperty<string> { Value = "DateTime" },
                DefaultValue = new GenericObjectProperty<JToken> { Value = JToken.FromObject(DateTime.Parse("2021-01-01T00:00:00Z").ToUniversalTime()) },
                AllowedValues = new GenericObjectProperty<GenericObjectProperty<JToken>[]>
                {
                    Value = new[]
                    {
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(DateTime.Parse("2020-01-01T00:00:00Z").ToUniversalTime()) },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(DateTime.Parse("2021-01-01T00:00:00Z").ToUniversalTime()) }
                    }
                }
            };

            var arrayParamObj = new ParameterObject
            {
                Type = new GenericObjectProperty<string> { Value = "Array" },
                DefaultValue = new GenericObjectProperty<JToken> { Value = JToken.FromObject(new JArray { 1, 2 }) },
                AllowedValues = new GenericObjectProperty<GenericObjectProperty<JToken>[]>
                {
                    Value = new[]
                    {
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(new JArray { 1, 2 }) },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(new JArray { 3, 4 }) }
                    }
                }
            };

            var objectParamObj = new ParameterObject
            {
                Type = new GenericObjectProperty<string> { Value = "Object" },
                DefaultValue = new GenericObjectProperty<JToken> { Value = JToken.FromObject(new JObject { ["a"] = 1 }) },
                AllowedValues = new GenericObjectProperty<GenericObjectProperty<JToken>[]>
                {
                    Value = new[]
                    {
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(new JObject { ["a"] = 1 }) },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject(new JObject { ["b"] = 2 }) }
                    }
                }
            };

            var path = ImmutableArray<string>.Empty;

            var stringParam = new Parameter("str", new GenericObjectProperty<ParameterObject> { Value = stringParamObj }, path, null);
            var intParam = new Parameter("int", new GenericObjectProperty<ParameterObject> { Value = intParamObj }, path, null);
            var floatParam = new Parameter("flt", new GenericObjectProperty<ParameterObject> { Value = floatParamObj }, path, null);
            var dateTimeParam = new Parameter("dt", new GenericObjectProperty<ParameterObject> { Value = dateTimeParamObj }, path, null);
            var arrayParam = new Parameter("arr", new GenericObjectProperty<ParameterObject> { Value = arrayParamObj }, path, null);
            var objectParam = new Parameter("obj", new GenericObjectProperty<ParameterObject> { Value = objectParamObj }, path, null);

            string[] allowedStrings;
            string defaultString;
            stringParam.TryAsConcreteType<string>(out allowedStrings, out defaultString).Should().BeTrue();
            allowedStrings.Should().BeEquivalentTo("a", "b", "c");
            defaultString.Should().Be("b");

            int[] allowedInts;
            int defaultInt;
            intParam.TryAsConcreteType<int>(out allowedInts, out defaultInt).Should().BeTrue();
            allowedInts.Should().BeEquivalentTo(new[] { 1, 2, 3 });
            defaultInt.Should().Be(2);

            double[] allowedDoubles;
            double defaultDouble;
            floatParam.TryAsConcreteType<double>(out allowedDoubles, out defaultDouble).Should().BeTrue();
            allowedDoubles.Should().BeEquivalentTo(new[] { 1.1, 2.2, 3.3 });
            defaultDouble.Should().Be(2.2);

            DateTime[] allowedDates;
            DateTime defaultDate;
            dateTimeParam.TryAsConcreteType<DateTime>(out allowedDates, out defaultDate).Should().BeTrue();
            allowedDates.Should().HaveCount(2);
            allowedDates[0].Should().Be(DateTime.Parse("2020-01-01T00:00:00Z").ToUniversalTime());
            allowedDates[1].Should().Be(DateTime.Parse("2021-01-01T00:00:00Z").ToUniversalTime());
            defaultDate.Should().Be(DateTime.Parse("2021-01-01T00:00:00Z").ToUniversalTime());

            JArray[] allowedArrays;
            JArray defaultArray;
            arrayParam.TryAsConcreteType<JArray>(out allowedArrays, out defaultArray).Should().BeTrue();
            allowedArrays.Should().HaveCount(2);
            defaultArray.Should().NotBeNull();
            defaultArray.Should().BeEquivalentTo(new JArray { 1, 2 });

            JObject[] allowedObjects;
            JObject defaultObject;
            objectParam.TryAsConcreteType<JObject>(out allowedObjects, out defaultObject).Should().BeTrue();
            allowedObjects.Should().HaveCount(2);
            defaultObject.Should().NotBeNull();
            defaultObject.Should().BeEquivalentTo(new JObject { ["a"] = 1 });
        }

        [Fact]
        public void LinterTests_Parameter_TryAsConcreteType_ReturnsFalseForUnsupportedType()
        {
            var paramObj = new ParameterObject
            {
                Type = new GenericObjectProperty<string> { Value = "String" },
                DefaultValue = new GenericObjectProperty<JToken> { Value = JToken.FromObject("a") },
                AllowedValues = new GenericObjectProperty<GenericObjectProperty<JToken>[]>
                {
                    Value = new[]
                    {
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject("a") },
                        new GenericObjectProperty<JToken> { Value = JToken.FromObject("b") }
                    }
                }
            };

            var path = ImmutableArray<string>.Empty;
            var param = new Parameter("str", new GenericObjectProperty<ParameterObject> { Value = paramObj }, path, null);

            bool result = param.TryAsConcreteType<bool>(out var allowed, out var def);

            result.Should().BeFalse();
            allowed.Should().BeNull();
            def.Should().BeFalse();
        }

        [Fact]
        public void LinterTests_PolicyDefinitionPropertiesRuleIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            var isEvaluateCalled = false;
            var testRule = new TestPolicyDefinitionPropertiesLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    isEvaluateCalled = true;

                    // Check that all properties are accessible with their values
                    expression.DisplayName.Value.ToString().Should().Be("Test Policy Display Name");
                    expression.Description.Value.ToString().Should().Be("Test Policy Description");
                    expression.Mode.Value.ToString().Should().Be("Indexed");
                    expression.PolicyType.Value.ToString().Should().Be("Custom");

                    // Check that line numbers are preserved
                    expression.DisplayName?.LineNumber.Should().Be(4);
                    expression.Description?.LineNumber.Should().Be(5);
                    expression.Mode?.LineNumber.Should().Be(6);
                    expression.PolicyType?.LineNumber.Should().Be(7);

                    return new LinterOutput[0];
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'displayName': 'Test Policy Display Name',
                    'description': 'Test Policy Description',
                    'mode': 'Indexed',
                    'policyType': 'Custom',
                    'policyRule': {
                        'if': {
                            'field': 'name',
                            'equals': 'test'
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);

            result.Should().BeEmpty();
            isEvaluateCalled.Should().BeTrue();
        }

        [Fact]
        public void LinterTests_ExternalEvaluationEnforcementSettingsRuleIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            var isEvaluateCalled = false;
            var testRule = new TestExternalEvaluationEnforcementSettingsLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    isEvaluateCalled = true;

                    // Check that all properties are accessible with their values
                    expression.MissingTokenAction?.Value.ToString().Should().Be("Fail");
                    expression.ResultLifespan?.Value.ToString().Should().Be("PT1H");
                    expression.RoleDefinitionIds?.Value.Should().BeOfType<Newtonsoft.Json.Linq.JArray>()
                        .Which.Should().BeEquivalentTo(new Newtonsoft.Json.Linq.JArray { "roleId1", "roleId2" });

                    // Check that line numbers are preserved
                    expression.MissingTokenAction?.LineNumber.Should().Be(8);
                    expression.ResultLifespan?.LineNumber.Should().Be(9);
                    expression.RoleDefinitionIds?.LineNumber.Should().Be(14);

                    // Check that endpoint settings are accessible
                    expression.EndpointSettings.Should().NotBeNull();
                    expression.EndpointSettings.Kind?.Value.ToString().Should().Be("HttpPost");

                    return new LinterOutput[0];
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'displayName': 'Test Policy with External Evaluation',
                    'mode': 'Indexed',
                    'policyType': 'Custom',
                    'externalEvaluationEnforcementSettings': {
                        'missingTokenAction': 'Fail',
                        'resultLifespan': 'PT1H',
                        'endpointSettings': {
                            'kind': 'HttpPost',
                            'details': { 'url': 'https://example.com' }
                        },
                        'roleDefinitionIds': ['roleId1', 'roleId2']
                    },
                    'policyRule': {
                        'if': {
                            'field': 'name',
                            'equals': '[claims().whatever]'
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);

            result.Should().BeEmpty();
            isEvaluateCalled.Should().BeTrue();
        }

        [Fact]
        public void LinterTests_EndpointSettingsRuleIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            var isEvaluateCalled = false;
            var testRule = new TestEndpointSettingsLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    isEvaluateCalled = true;

                    // Check that all properties are accessible with their values
                    expression.Kind?.Value.ToString().Should().Be("HttpPost");
                    expression.Details?.Value?.ToString().Should().Contain("https://example.com");

                    // Check that line numbers are preserved
                    expression.Kind?.LineNumber.Should().Be(11);
                    expression.Details?.LineNumber.Should().Be(12);

                    return new LinterOutput[0];
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'displayName': 'Test Policy with Endpoint Settings',
                    'mode': 'Indexed',
                    'policyType': 'Custom',
                    'externalEvaluationEnforcementSettings': {
                        'missingTokenAction': 'Fail',
                        'resultLifespan': 'PT1H',
                        'endpointSettings': {
                            'kind': 'HttpPost',
                            'details': { 'url': 'https://example.com' }
                        }
                    },
                    'policyRule': {
                        'if': {
                            'field': 'name',
                            'equals': 'whatever'
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);

            result.Should().BeEmpty();
            isEvaluateCalled.Should().BeTrue();
        }

        [Fact]
        public void LinterTests_PolicyDefinitionNamePropertyRuleIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            var isEvaluateCalled = false;
            var testRule = new TestPolicyDefinitionLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    isEvaluateCalled = true;

                    // Check that name property is accessible with its value
                    expression.Name?.Value.ToString().Should().Be("TestPolicyName");

                    // Check that line number is preserved
                    expression.Name?.LineNumber.Should().Be(3);

                    // Check that properties are accessible
                    expression.Properties.Should().NotBeNull();
                    expression.Properties.DisplayName.Value.ToString().Should().Be("Test Policy with Name");

                    return new LinterOutput[0];
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'name': 'TestPolicyName',
                'properties': {
                    'displayName': 'Test Policy with Name',
                    'mode': 'Indexed',
                    'policyType': 'Custom',
                    'policyRule': {
                        'if': {
                            'field': 'name',
                            'equals': 'test'
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);

            result.Should().BeEmpty();
            isEvaluateCalled.Should().BeTrue();
        }

        [Fact]
        public void LinterTests_ContextContainsExternalEvaluationEnforcementSettings()
        {
            var mockMetadata = new MockTypeMetadata();
            var isContextValidated = false;

            var testRule = new TestLeafConditionLinterRule(descriptionFormat: "Test rule was invoked")
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    context.Should().NotBeNull();
                    context.ExternalEvaluationEnforcementSettings.Should().NotBeNull();
                    context.ExternalEvaluationEnforcementSettings.MissingTokenAction?.Value.ToString().Should().Be("Fail");
                    context.ExternalEvaluationEnforcementSettings.ResultLifespan?.Value.ToString().Should().Be("PT1H");
                    context.ExternalEvaluationEnforcementSettings.RoleDefinitionIds?.Value.Should().BeOfType<Newtonsoft.Json.Linq.JArray>()
                        .Which.Should().BeEquivalentTo(new Newtonsoft.Json.Linq.JArray { "roleId1", "roleId2" });
                    context.ExternalEvaluationEnforcementSettings.EndpointSettings.Should().NotBeNull();
                    context.ExternalEvaluationEnforcementSettings.EndpointSettings.Kind?.Value.ToString().Should().Be("HttpPost");

                    isContextValidated = true;
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'displayName': 'Test Policy with External Evaluation',
                    'mode': 'Indexed',
                    'policyType': 'Custom',
                    'externalEvaluationEnforcementSettings': {
                        'missingTokenAction': 'Fail',
                        'resultLifespan': 'PT1H',
                        'endpointSettings': {
                            'kind': 'HttpPost',
                            'details': { 'url': 'https://example.com' }
                        },
                        'roleDefinitionIds': ['roleId1', 'roleId2']
                    },
                    'policyRule': {
                        'if': {
                            'field': 'name',
                            'equals': '[claims().whatever]'
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);

            result.Should().BeEmpty();
            isContextValidated.Should().BeTrue();
        }

        [Fact]
        public void LinterTests_ContextExternalEvaluationEnforcementSettingsIsNullWhenNotSpecified()
        {
            var mockMetadata = new MockTypeMetadata();
            var isContextValidated = false;

            var testRule = new TestLeafConditionLinterRule(descriptionFormat: "Test rule was invoked")
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    context.Should().NotBeNull();
                    context.ExternalEvaluationEnforcementSettings.Should().BeNull();

                    isContextValidated = true;
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'displayName': 'Test Policy without External Evaluation',
                    'mode': 'Indexed',
                    'policyType': 'Custom',
                    'policyRule': {
                        'if': { 'field': 'name', 'equals': 'whatever' },
                        'then': { 'effect': 'deny' }
                    }
                }
            }";

            var result = linter.Lint(policy);

            result.Should().BeEmpty();
            isContextValidated.Should().BeTrue();
        }

        [Fact]
        public void LinterTests_ReferenceRuleIsInvoked_ExternalEvaluationClaimsReference()
        {
            var mockMetadata = new MockTypeMetadata();
            var references = new List<Reference>();
            var testRule = new TestReferenceLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    references.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'displayName': 'External Evaluation Policy with Claims',
                    'mode': 'Indexed',
                    'policyType': 'Custom',
                    'externalEvaluationEnforcementSettings': {
                        'missingTokenAction': 'Fail',
                        'resultLifespan': 'PT2H',
                        'endpointSettings': {
                            'kind': 'HttpPost',
                            'details': { 'url': 'https://compliance-service.example.com/evaluate' }
                        },
                        'roleDefinitionIds': ['8e3af657-a8ff-443c-a75c-2fe8c4bcb635']
                    },
                    'policyRule': {
                        'if': {
                            'allOf': [
                                { 'field': 'location', 'equals': ""[claims().compliance.region.approved]"" },
                                { 'value': ""[claims().security.classification]"", 'in': ['public', 'internal'] },
                                { 'field': 'tags.environment', 'equals': ""[claims().deployment.environment.validated]"" }
                            ]
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);
            result.Should().BeEmpty();

            // Filter to only PolicyTokenClaims references
            var claimsReferences = references.Where(r => r.Kind == ReferenceKind.PolicyTokenClaims).ToList();
            claimsReferences.Should().HaveCount(3);

            // Check the first claims reference - compliance region data from external evaluation
            var complianceRegionRef = claimsReferences.FirstOrDefault(r => r.PathSegments.Last() == "equals" && r.PathSegments.Contains("allOf[0]"));
            complianceRegionRef.Should().NotBeNull();
            complianceRegionRef.Kind.Should().Be(ReferenceKind.PolicyTokenClaims);
            complianceRegionRef.Identifier.Should().Be("compliance.region.approved"); // Complex property path
            complianceRegionRef.PropertySelectionPath.Should().NotBeNull();
            complianceRegionRef.PropertySelectionPath.Path.Should().BeEquivalentTo(new[] { "compliance", "region", "approved" });

            // Check the second claims reference - security classification from external evaluation
            var securityClassificationRef = claimsReferences.FirstOrDefault(r => r.PathSegments.Last() == "value");
            securityClassificationRef.Should().NotBeNull();
            securityClassificationRef.Kind.Should().Be(ReferenceKind.PolicyTokenClaims);
            securityClassificationRef.Identifier.Should().Be("security.classification"); // Nested property path
            securityClassificationRef.PropertySelectionPath.Should().NotBeNull();
            securityClassificationRef.PropertySelectionPath.Path.Should().BeEquivalentTo(new[] { "security", "classification" });

            // Check the third claims reference - deployment environment validation from external evaluation
            var deploymentEnvRef = claimsReferences.FirstOrDefault(r => r.PathSegments.Last() == "equals" && r.PathSegments.Contains("allOf[2]"));
            deploymentEnvRef.Should().NotBeNull();
            deploymentEnvRef.Kind.Should().Be(ReferenceKind.PolicyTokenClaims);
            deploymentEnvRef.Identifier.Should().Be("deployment.environment.validated"); // Complex nested path
            deploymentEnvRef.PropertySelectionPath.Should().NotBeNull();
            deploymentEnvRef.PropertySelectionPath.Path.Should().BeEquivalentTo(new[] { "deployment", "environment", "validated" });
        }

        [Fact]
        public void LinterTests_ExternalEvaluationEnforcementSettings_PolicyParameterReferences()
        {
            var mockMetadata = new MockTypeMetadata();
            var references = new List<Reference>();
            var testRule = new TestReferenceLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    references.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'displayName': 'External Evaluation Policy with Parameter and Field References',
                    'mode': 'Indexed',
                    'policyType': 'Custom',
                    'parameters': {
                        'tokenActionParam': {
                            'type': 'string',
                            'defaultValue': 'Fail',
                            'allowedValues': ['Fail', 'Allow']
                        },
                        'lifespanParam': {
                            'type': 'string',
                            'defaultValue': 'PT2H'
                        },
                        'endpointKindParam': {
                            'type': 'string',
                            'defaultValue': 'HttpPost'
                        },
                        'baseUrlParam': {
                            'type': 'string',
                            'defaultValue': 'https://compliance-service.example.com'
                        }
                    },
                    'externalEvaluationEnforcementSettings': {
                        'missingTokenAction': ""[parameters('tokenActionParam')]"",
                        'resultLifespan': ""[parameters('lifespanParam')]"",
                        'endpointSettings': {
                            'kind': ""[parameters('endpointKindParam')]"",
                            'details': {
                                'url': ""[parameters('baseUrlParam')]"",
                                'resourceType': ""[field('type')]"",
                                'environment': ""[field('tags.environment')]""
                            }
                        },
                        'roleDefinitionIds': ['8e3af657-a8ff-443c-a75c-2fe8c4bcb635']
                    },
                    'policyRule': {
                        'if': {
                            'field': 'location',
                            'equals': 'eastus'
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);
            result.Should().BeEmpty();

            // Filter to only policy parameter references
            var parameterReferences = references.Where(r => r.Kind == ReferenceKind.PolicyParameterName).ToList();
            parameterReferences.Should().HaveCount(4); // tokenActionParam, lifespanParam, endpointKindParam, baseUrlParam

            // Filter to only resource field references
            var fieldReferences = references.Where(r => r.Kind == ReferenceKind.ResourceField).ToList();
            fieldReferences.Should().HaveCount(3); // location (in policyRule), type, tags.environment

            // Check the parameter reference in missingTokenAction
            var tokenActionParamRef = parameterReferences.FirstOrDefault(r =>
                r.Identifier == "tokenActionParam" &&
                r.PathSegments.Contains("externalEvaluationEnforcementSettings") &&
                r.PathSegments.Last() == "missingTokenAction");
            tokenActionParamRef.Should().NotBeNull();
            tokenActionParamRef.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            tokenActionParamRef.IsResolved.Should().BeTrue();

            // Check the parameter reference in resultLifespan
            var lifespanParamRef = parameterReferences.FirstOrDefault(r =>
                r.Identifier == "lifespanParam" &&
                r.PathSegments.Contains("externalEvaluationEnforcementSettings") &&
                r.PathSegments.Last() == "resultLifespan");
            lifespanParamRef.Should().NotBeNull();
            lifespanParamRef.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            lifespanParamRef.IsResolved.Should().BeTrue();

            // Check the parameter reference in endpointSettings.kind
            var endpointKindParamRef = parameterReferences.FirstOrDefault(r =>
                r.Identifier == "endpointKindParam" &&
                r.PathSegments.Contains("endpointSettings") &&
                r.PathSegments.Last() == "kind");
            endpointKindParamRef.Should().NotBeNull();
            endpointKindParamRef.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            endpointKindParamRef.IsResolved.Should().BeTrue();
            endpointKindParamRef.Parent.Should().BeOfType<TemplateLanguageExpression>()
                .Subject.Parent.Should().BeOfType<Property>()
                .Subject.Name.Should().Be("kind");

            // Check the parameter reference in endpointSettings.details (baseUrlParam)
            var baseUrlParamRef = parameterReferences.FirstOrDefault(r =>
                r.Identifier == "baseUrlParam" &&
                r.PathSegments.Contains("endpointSettings") &&
                r.PathSegments.Last() == "details");
            baseUrlParamRef.Should().NotBeNull();
            baseUrlParamRef.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            baseUrlParamRef.IsResolved.Should().BeTrue();

            // Check the resource field reference for tags.environment
            var tagsEnvironmentRef = fieldReferences.FirstOrDefault(r =>
                r.Identifier == "tags.environment" &&
                r.PathSegments.Contains("endpointSettings") &&
                r.PathSegments.Last() == "details");
            tagsEnvironmentRef.Should().NotBeNull();
            tagsEnvironmentRef.Kind.Should().Be(ReferenceKind.ResourceField);
            tagsEnvironmentRef.IsResolved.Should().BeTrue();
            tagsEnvironmentRef.Identifier.Should().Be("tags.environment");

            // Check the resource field reference for type
            var typeRef = fieldReferences.FirstOrDefault(r =>
                r.Identifier == "type" &&
                r.PathSegments.Contains("endpointSettings") &&
                r.PathSegments.Last() == "details");
            typeRef.Should().NotBeNull();
            typeRef.Kind.Should().Be(ReferenceKind.ResourceField);
            typeRef.IsResolved.Should().BeTrue();
            typeRef.Identifier.Should().Be("type");

            // Check the resource field reference in policyRule (location)
            var locationRef = fieldReferences.FirstOrDefault(r =>
                r.Identifier == "location" &&
                r.PathSegments.Contains("policyRule"));
            locationRef.Should().NotBeNull();
            locationRef.Kind.Should().Be(ReferenceKind.ResourceField);
            locationRef.IsResolved.Should().BeTrue();
            locationRef.Identifier.Should().Be("location");
        }

        [Fact]
        public void LinterTests_EndpointSettings_ReferenceRuleIsInvoked()
        {
            var mockMetadata = new MockTypeMetadata();
            var paramRefFound = false;
            var fieldRefFound = false;

            var testRule = new TestReferenceLinterRule
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    // Check for parameter reference in endpointSettings
                    if (expression.Kind == ReferenceKind.PolicyParameterName &&
                        expression.Identifier == "testParam" &&
                        expression.PathSegments.Contains("endpointSettings"))
                    {
                        expression.IsResolved.Should().BeTrue();
                        expression.Parent.Should().BeOfType<TemplateLanguageExpression>()
                            .Subject.Parent.Should().BeOfType<Property>()
                            .Subject.Name.Should().Be("details");
                        paramRefFound = true;
                    }

                    // Check for resource field reference in endpointSettings
                    if (expression.Kind == ReferenceKind.ResourceField &&
                        expression.Identifier == "id" &&
                        expression.PathSegments.Contains("endpointSettings"))
                    {
                        expression.IsResolved.Should().BeTrue();
                        expression.Parent.Should().BeOfType<TemplateLanguageExpression>()
                            .Subject.Parent.Should().BeOfType<Property>()
                            .Subject.Name.Should().Be("details");
                        fieldRefFound = true;
                    }

                    return Enumerable.Empty<LinterOutput>();
                }
            };

            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"
            {
                'properties': {
                    'displayName': 'Endpoint Settings Reference Rule Test',
                    'mode': 'Indexed',
                    'policyType': 'Custom',
                    'parameters': {
                        'testParam': {
                            'type': 'string',
                            'defaultValue': 'testValue'
                        }
                    },
                    'externalEvaluationEnforcementSettings': {
                        'missingTokenAction': 'Fail',
                        'resultLifespan': 'PT1H',
                        'endpointSettings': {
                            'kind': 'HttpPost',
                            'details': {
                                'propA': ""[parameters('testParam')]"",
                                'propB': ""[field('id')]""
                            }
                        }
                    },
                    'policyRule': {
                        'if': {
                            'field': 'location',
                            'equals': 'eastus'
                        },
                        'then': {
                            'effect': 'deny'
                        }
                    }
                }
            }";

            var result = linter.Lint(policy);

            result.Should().BeEmpty();
            paramRefFound.Should().BeTrue();
            fieldRefFound.Should().BeTrue();
        }

        [Fact]
        public void LinterTests_AcceptsNullFilePath()
        {
            var mockMetadata = new MockTypeMetadata();
            var testRule = new TestLeafConditionLinterRule();
            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"{ 'properties': { 'mode': 'Indexed', 'policyRule': { 'if': { 'value': 1, 'equals': 1 }, 'then': { 'effect': 'deny' } } } }";

            // Null file path should be allowed
            Action act = () => linter.Lint(policy, filePath: null);

            act.Should().NotBeNull();
        }

        [Fact]
        public void LinterTests_ThrowsExceptionForEmptyFilePath()
        {
            var mockMetadata = new MockTypeMetadata();
            var testRule = new TestLeafConditionLinterRule();
            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"{ 'properties': { 'mode': 'Indexed', 'policyRule': { 'if': { 'value': 1, 'equals': 1 }, 'then': { 'effect': 'deny' } } } }";

            Action act = () => linter.Lint(policy, filePath: string.Empty);

            act.Should().Throw<ArgumentException>()
                .WithMessage("*file path must be an absolute path*")
                .And.ParamName.Should().Be("filePath");
        }

        [Fact]
        public void LinterTests_ThrowsExceptionForRelativeFilePath()
        {
            var mockMetadata = new MockTypeMetadata();
            var testRule = new TestLeafConditionLinterRule();
            var linter = new PolicyLinter(new[] { testRule }, mockMetadata);

            var policy = @"{ 'properties': { 'mode': 'Indexed', 'policyRule': { 'if': { 'value': 1, 'equals': 1 }, 'then': { 'effect': 'deny' } } } }";

            Action act = () => linter.Lint(policy, filePath: "test-policy.json");

            act.Should().Throw<ArgumentException>()
                .WithMessage("*file path must be an absolute path*")
                .And.ParamName.Should().Be("filePath");
        }
    }
}
