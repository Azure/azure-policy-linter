namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Tests
{
    using System;
    using System.Collections.Generic;
    using FluentAssertions;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Expressions;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Xunit;

    /// <summary>
    /// Tests for parsing policy definitions and expressions.
    /// </summary>
    public class ParsingTests
    {
        [Fact]
        public void LinterTests_Parsing_ParsePolicyDefinitionAsGenericObjectsWithLineInfo()
        {
            var policy = @"
{
    'properties': {
        'displayName': 'Test Policy',
        'description': 'A policy for testing line information',
        'mode': 'Indexed',
        'parameters': {
            'allowedLocations': {
                'type': 'Array',
                'metadata': {
                    'displayName': 'Allowed locations',
                    'description': 'The list of allowed locations'
                },
                'defaultValue': [
                    'eastus',
                    'westus'
                ]
            },
            'effect': {
                'type': 'String',
                'defaultValue': 'deny',
                'allowedValues': [
                    'audit',
                    'deny',
                    'disabled'
                ]
            }
        },
        'policyRule': {
            'if': {
                'allOf': [
                    {
                        'field': 'location',
                        'notIn': '[parameters(\'allowedLocations\')]'
                    },
                    {
                        'not': {
                            'count': {
                                'value': [ 1, 2, 3],
                                'name': 'myArr',
                                'where': {
                                    'value': '[current(\'myArr\')]',
                                    'greater': 0
                                }
                            },
                            'equals': 1
                        }
                    }
                ]
            },
            'then': {
                'effect': '[parameters(\'effect\')]'
            }
        }
    }
}";

            var policyDefinitionObject = policy.FromJson<PolicyDefinitionObject>(settings: PolicySerializerSettings.Settings);
            policyDefinitionObject.Should().NotBeNull();
            policyDefinitionObject.Properties.Should().NotBeNull();

            var definitionProperties = policyDefinitionObject.Properties;
            definitionProperties.LineNumber.Should().Be(3);
            definitionProperties.LinePosition.Should().Be(19);

            var displayName = definitionProperties.Value.DisplayName;
            displayName.Should().NotBeNull();
            displayName.LineNumber.Should().Be(4);
            displayName.LinePosition.Should().Be(36);

            var description = definitionProperties.Value.Description;
            description.Should().NotBeNull();
            description.LineNumber.Should().Be(5);
            description.LinePosition.Should().Be(62);

            var mode = definitionProperties.Value.Mode;
            mode.Should().NotBeNull();
            mode.LineNumber.Should().Be(6);
            mode.LinePosition.Should().Be(25);

            var parameters = definitionProperties.Value.Parameters;
            parameters.Should().NotBeNull();
            parameters.LineNumber.Should().Be(7);
            parameters.LinePosition.Should().Be(23);

            var allowedLocations = parameters.Value["allowedLocations"];
            allowedLocations.Should().NotBeNull();
            allowedLocations.LineNumber.Should().Be(8);
            allowedLocations.LinePosition.Should().Be(33);

            var allowedLocationsType = allowedLocations.Value.Type;
            allowedLocationsType.Should().NotBeNull();
            allowedLocationsType.LineNumber.Should().Be(9);
            allowedLocationsType.LinePosition.Should().Be(31);

            var allowedLocationsDefaultValue = allowedLocations.Value.DefaultValue;
            allowedLocationsDefaultValue.Should().NotBeNull();
            allowedLocationsDefaultValue.LineNumber.Should().Be(14);
            allowedLocationsDefaultValue.LinePosition.Should().Be(33);

            var effectParameter = parameters.Value["effect"];
            effectParameter.Should().NotBeNull();
            effectParameter.LineNumber.Should().Be(19);
            effectParameter.LinePosition.Should().Be(23);

            var effectType = effectParameter.Value.Type;
            effectType.Should().NotBeNull();
            effectType.LineNumber.Should().Be(20);
            effectType.LinePosition.Should().Be(32);

            var effectDefaultValue = effectParameter.Value.DefaultValue;
            effectDefaultValue.Should().NotBeNull();
            effectDefaultValue.LineNumber.Should().Be(21);
            effectDefaultValue.LinePosition.Should().Be(38);

            var effectAllowedValues = effectParameter.Value.AllowedValues;
            effectAllowedValues.Should().NotBeNull();
            effectAllowedValues.LineNumber.Should().Be(22);
            effectAllowedValues.LinePosition.Should().Be(34);

            var policyRule = definitionProperties.Value.PolicyRule;
            policyRule.Should().NotBeNull();
            policyRule.LineNumber.Should().Be(29);
            policyRule.LinePosition.Should().Be(23);

            var ifCondition = policyRule.Value.If;
            ifCondition.Should().NotBeNull();
            ifCondition.LineNumber.Should().Be(30);
            ifCondition.LinePosition.Should().Be(19);

            var allOfCondition = ifCondition.Value.AllOf;
            allOfCondition.Should().NotBeNull();
            allOfCondition.LineNumber.Should().Be(31);
            allOfCondition.LinePosition.Should().Be(26);

            var fieldLeaf = allOfCondition.Value[0];
            fieldLeaf.Should().NotBeNull();
            fieldLeaf.LineNumber.Should().Be(32);
            fieldLeaf.LinePosition.Should().Be(21);

            var fieldAccessor = fieldLeaf.Value.Field;
            fieldAccessor.Should().NotBeNull();
            fieldAccessor.LineNumber.Should().Be(33);
            fieldAccessor.LinePosition.Should().Be(43);

            var notInOperator = fieldLeaf.Value.NotIn;
            notInOperator.Should().NotBeNull();
            notInOperator.LineNumber.Should().Be(34);
            notInOperator.LinePosition.Should().Be(69);

            var notCondition = allOfCondition.Value[1];
            notCondition.Should().NotBeNull();
            notCondition.LineNumber.Should().Be(36);
            notCondition.LinePosition.Should().Be(21);

            var countCondition = notCondition.Value.Not.Value;
            countCondition.Should().NotBeNull();
            countCondition.LineNumber.Should().Be(37);
            countCondition.LinePosition.Should().Be(32);

            var countObject = countCondition.Value.Count;
            countObject.Should().NotBeNull();
            countObject.LineNumber.Should().Be(38);
            countObject.LinePosition.Should().Be(38);

            var countValue = countObject.Value.Value;
            countValue.Should().NotBeNull();
            countValue.LineNumber.Should().Be(39);
            countValue.LinePosition.Should().Be(42);

            var countName = countObject.Value.Name;
            countName.Should().NotBeNull();
            countName.LineNumber.Should().Be(40);
            countName.LinePosition.Should().Be(47);

            var countWhere = countObject.Value.Where;
            countWhere.Should().NotBeNull();
            countWhere.LineNumber.Should().Be(41);
            countWhere.LinePosition.Should().Be(42);

            var countWhereValue = countWhere.Value.Value;
            countWhereValue.Should().NotBeNull();
            countWhereValue.LineNumber.Should().Be(42);
            countWhereValue.LinePosition.Should().Be(67);

            var countWhereGreater = countWhere.Value.Greater;
            countWhereGreater.Should().NotBeNull();
            countWhereGreater.LineNumber.Should().Be(43);
            countWhereGreater.LinePosition.Should().Be(48);

            var countEqualsOperator = countCondition.Value.EqualsOperator;
            countEqualsOperator.Should().NotBeNull();
            countEqualsOperator.LineNumber.Should().Be(46);
            countEqualsOperator.LinePosition.Should().Be(39);

            var then = policyRule.Value.Then;
            then.Should().NotBeNull();
            then.LineNumber.Should().Be(51);
            then.LinePosition.Should().Be(21);

            var effect = then.Value.Effect;
            effect.Should().NotBeNull();
            effect.LineNumber.Should().Be(52);
            effect.LinePosition.Should().Be(52);
        }

        [Fact]
        public void LinterTests_Parsing_MetadataPropertyHasCorrectLineInfo()
        {
            var policy = @"
{
    'properties': {
        'displayName': 'Test Policy',
        'mode': 'Indexed',
        'metadata': {
            'category': 'Testing',
            'posId': '12345678-1234-1234-1234-123456789012'
        },
        'policyRule': {
            'if': {
                'field': 'type',
                'equals': 'Microsoft.Compute/virtualMachines'
            },
            'then': {
                'effect': 'deny'
            }
        }
    }
}";

            var policyDefinitionObject = policy.FromJson<PolicyDefinitionObject>(settings: PolicySerializerSettings.Settings);
            var mockMetadata = new MockTypeMetadata();
            var policyDefinition = new PolicyDefinition(
                policyDefinitionObject,
                mockMetadata);

            // Verify metadata property has correct line info
            var metadata = policyDefinition.Properties.Metadata;
            metadata.Should().NotBeNull();
            metadata.LineNumber.Should().Be(6);
            metadata.LinePosition.Should().Be(21);
        }

        [Fact]
        public void LinterTests_Parsing_PolicyExpressionsHavePathAndLineInfo()
        {
            var policy = @"
{
    'properties': {
        'displayName': 'Test Policy',
        'description': 'A policy for testing line information',
        'mode': 'Indexed',
        'parameters': {
            'allowedLocations': {
                'type': 'Array',
                'metadata': {
                    'displayName': 'Allowed locations',
                    'description': 'The list of allowed locations'
                },
                'defaultValue': [
                    'eastus',
                    'westus'
                ]
            },
            'effect': {
                'type': 'String',
                'defaultValue': 'deny',
                'allowedValues': [
                    'audit',
                    'deny',
                    'disabled'
                ]
            }
        },
        'policyRule': {
            'if': { //L30
                'allOf': [
                    {
                        'field': 'location',
                        'notIn': '[parameters(\'allowedLocations\')]'
                    },
                    {
                        'not': {
                            'count': {
                                'value': [ 1, 2, 3],
                                'name': 'myArr',
                                'where': { // L41
                                    'value': '[current(\'myArr\')]',
                                    'greater': 0
                                }
                            },
                            'equals': 1
                        }
                    }
                ]
            },
            'then': {
                'effect': '[parameters(\'effect\')]'
            }
        }
    }
}";

            // Parse the policy definition
            var policyDefinitionObject = policy.FromJson<PolicyDefinitionObject>(settings: PolicySerializerSettings.Settings);

            // Create a PolicyDefinition instance from the parsed object
            var mockMetadata = new MockTypeMetadata();
            var policyDefinition = new PolicyDefinition(
                policyDefinitionObject,
                mockMetadata);

            // Use a dictionary to store expressions by their path for assertion
            var expressionsWithLineInfo = new Dictionary<string, PolicyExpression>();
            var referenceExpressionsWithLineInfo = new Dictionary<string, PolicyExpression>();
            var templateLanguageExpressionsWithLineInfo = new Dictionary<string, PolicyExpression>();

            // Create a visitor to traverse the expression tree
            var visitor = new PolicyExpressionVisitor
            {
                Visit = (expression) =>
                {
                    // Store references and template language expressions separately
                    // These are "policy expressions" that aren't directly connected to the policy definition structure.
                    // For example, the leaf condition { value: "[field('x')]", equals: 1 } will translate into 3 expressions:
                    // - The value property, the language expression and the reference to the field x. All should have the same path and line info.
                    if (expression is Reference reference)
                    {
                        referenceExpressionsWithLineInfo[reference.Path] = reference;
                    }
                    else if (expression is TemplateLanguageExpression templateLanguageExpression)
                    {
                        // Template language expressions are also collected separately.
                        templateLanguageExpressionsWithLineInfo[templateLanguageExpression.Path] = templateLanguageExpression;
                    }
                    else
                    {
                        expressionsWithLineInfo[expression.Path] = expression;
                    }
                }
            };

            // Visit all expressions in the policy definition
            policyDefinition.Visit(visitor);

            // Verify that we collected expressions
            expressionsWithLineInfo.Should().NotBeEmpty();

            // Verify properties node
            var propertiesPath = "properties";
            expressionsWithLineInfo.Should().ContainKey(propertiesPath);
            expressionsWithLineInfo[propertiesPath].LineNumber.Should().Be(3);
            expressionsWithLineInfo[propertiesPath].LinePosition.Should().Be(19);

            // Verify policy rule
            var policyRulePath = "properties.policyRule";
            expressionsWithLineInfo.Should().ContainKey(policyRulePath);
            expressionsWithLineInfo[policyRulePath].LineNumber.Should().Be(29);
            expressionsWithLineInfo[policyRulePath].LinePosition.Should().Be(23);

            // Verify if condition
            var ifPath = "properties.policyRule.if";
            expressionsWithLineInfo.Should().ContainKey(ifPath);
            expressionsWithLineInfo[ifPath].LineNumber.Should().Be(30);
            expressionsWithLineInfo[ifPath].LinePosition.Should().Be(19);

            // Verify allOf condition
            var allOfPath = "properties.policyRule.if.allOf";
            expressionsWithLineInfo.Should().ContainKey(allOfPath);
            expressionsWithLineInfo[allOfPath].LineNumber.Should().Be(31);
            expressionsWithLineInfo[allOfPath].LinePosition.Should().Be(26);

            // Verify field condition
            var fieldLeafPath = "properties.policyRule.if.allOf[0]";
            expressionsWithLineInfo.Should().ContainKey(fieldLeafPath);
            expressionsWithLineInfo[fieldLeafPath].LineNumber.Should().Be(32);
            expressionsWithLineInfo[fieldLeafPath].LinePosition.Should().Be(21);

            // Verify field accessor
            var fieldPath = "properties.policyRule.if.allOf[0].field";
            expressionsWithLineInfo.Should().ContainKey(fieldPath);
            expressionsWithLineInfo[fieldPath].LineNumber.Should().Be(33);
            expressionsWithLineInfo[fieldPath].LinePosition.Should().Be(43);

            // The field accessor should also have corresponding reference expression
            referenceExpressionsWithLineInfo.Should().ContainKey(fieldPath);
            referenceExpressionsWithLineInfo[fieldPath].LineNumber.Should().Be(33);
            referenceExpressionsWithLineInfo[fieldPath].LinePosition.Should().Be(43);

            // Verify notIn operator
            var notInPath = "properties.policyRule.if.allOf[0].notIn";
            expressionsWithLineInfo.Should().ContainKey(notInPath);
            expressionsWithLineInfo[notInPath].LineNumber.Should().Be(34);
            expressionsWithLineInfo[notInPath].LinePosition.Should().Be(69);

            // The notIn operator should also have corresponding reference and template function expressions
            referenceExpressionsWithLineInfo.Should().ContainKey(notInPath);
            referenceExpressionsWithLineInfo[notInPath].LineNumber.Should().Be(34);
            referenceExpressionsWithLineInfo[notInPath].LinePosition.Should().Be(69);

            templateLanguageExpressionsWithLineInfo.Should().ContainKey(notInPath);
            templateLanguageExpressionsWithLineInfo[notInPath].LineNumber.Should().Be(34);
            templateLanguageExpressionsWithLineInfo[notInPath].LinePosition.Should().Be(69);

            // Not conditions inside of quantifiers are a bit strange.
            // They're strange because we don't have a representation of the object containing the not property. The quantifier object we create to represent the not condition is for the actual condition inside the "not" property.
            // This is equivalent to how 'allOf' quantifier object represents the conditions inside the 'allOf' property and not the object wrapping the 'allOf' property.
            var notPath = "properties.policyRule.if.allOf[1]";
            expressionsWithLineInfo.Should().NotContainKey(notPath);

            // Verify not value
            var notValuePath = "properties.policyRule.if.allOf[1].not";
            expressionsWithLineInfo.Should().ContainKey(notValuePath);
            expressionsWithLineInfo[notValuePath].LineNumber.Should().Be(37);
            expressionsWithLineInfo[notValuePath].LinePosition.Should().Be(32);

            // Verify count
            var countPath = "properties.policyRule.if.allOf[1].not.count";
            expressionsWithLineInfo.Should().ContainKey(countPath);
            expressionsWithLineInfo[countPath].LineNumber.Should().Be(38);
            expressionsWithLineInfo[countPath].LinePosition.Should().Be(38);

            // Verify count value
            var countValuePath = "properties.policyRule.if.allOf[1].not.count.value";
            expressionsWithLineInfo.Should().ContainKey(countValuePath);
            expressionsWithLineInfo[countValuePath].LineNumber.Should().Be(39);
            expressionsWithLineInfo[countValuePath].LinePosition.Should().Be(42);

            // Verify count name
            var countNamePath = "properties.policyRule.if.allOf[1].not.count.name";
            expressionsWithLineInfo.Should().ContainKey(countNamePath);
            expressionsWithLineInfo[countNamePath].LineNumber.Should().Be(40);
            expressionsWithLineInfo[countNamePath].LinePosition.Should().Be(47);

            // Verify count where
            var countWherePath = "properties.policyRule.if.allOf[1].not.count.where";
            expressionsWithLineInfo.Should().ContainKey(countWherePath);
            expressionsWithLineInfo[countWherePath].LineNumber.Should().Be(41);
            expressionsWithLineInfo[countWherePath].LinePosition.Should().Be(42);

            // Verify count where value
            var countWhereValuePath = "properties.policyRule.if.allOf[1].not.count.where.value";
            expressionsWithLineInfo.Should().ContainKey(countWhereValuePath);
            expressionsWithLineInfo[countWhereValuePath].LineNumber.Should().Be(42);
            expressionsWithLineInfo[countWhereValuePath].LinePosition.Should().Be(67);

            // The count where value accessor should also have corresponding reference and template function expressions
            referenceExpressionsWithLineInfo.Should().ContainKey(countWhereValuePath);
            referenceExpressionsWithLineInfo[countWhereValuePath].LineNumber.Should().Be(42);
            referenceExpressionsWithLineInfo[countWhereValuePath].LinePosition.Should().Be(67);

            templateLanguageExpressionsWithLineInfo.Should().ContainKey(countWhereValuePath);
            templateLanguageExpressionsWithLineInfo[countWhereValuePath].LineNumber.Should().Be(42);
            templateLanguageExpressionsWithLineInfo[countWhereValuePath].LinePosition.Should().Be(67);

            // Verify count where greater
            var countWhereGreaterPath = "properties.policyRule.if.allOf[1].not.count.where.greater";
            expressionsWithLineInfo.Should().ContainKey(countWhereGreaterPath);
            expressionsWithLineInfo[countWhereGreaterPath].LineNumber.Should().Be(43);
            expressionsWithLineInfo[countWhereGreaterPath].LinePosition.Should().Be(48);

            // Verify equals operator
            var equalsPath = "properties.policyRule.if.allOf[1].not.equals";
            expressionsWithLineInfo.Should().ContainKey(equalsPath);
            expressionsWithLineInfo[equalsPath].LineNumber.Should().Be(46);
            expressionsWithLineInfo[equalsPath].LinePosition.Should().Be(39);

            // Verify then
            var thenPath = "properties.policyRule.then";
            expressionsWithLineInfo.Should().ContainKey(thenPath);
            expressionsWithLineInfo[thenPath].LineNumber.Should().Be(51);
            expressionsWithLineInfo[thenPath].LinePosition.Should().Be(21);

            // Verify effect
            var effectPath = "properties.policyRule.then.effect";
            expressionsWithLineInfo.Should().ContainKey(effectPath);
            expressionsWithLineInfo[effectPath].LineNumber.Should().Be(52);
            expressionsWithLineInfo[effectPath].LinePosition.Should().Be(52);

            // The effect should also have corresponding reference and template function expressions
            referenceExpressionsWithLineInfo.Should().ContainKey(effectPath);
            referenceExpressionsWithLineInfo[effectPath].LineNumber.Should().Be(52);
            referenceExpressionsWithLineInfo[effectPath].LinePosition.Should().Be(52);

            templateLanguageExpressionsWithLineInfo.Should().ContainKey(effectPath);
            templateLanguageExpressionsWithLineInfo[effectPath].LineNumber.Should().Be(52);
            templateLanguageExpressionsWithLineInfo[effectPath].LinePosition.Should().Be(52);
        }

        [Theory]
        [InlineData("equals", "'eastus'")]
        [InlineData("notEquals", "'westus'")]
        [InlineData("like", "'eastus*'")]
        [InlineData("notLike", "'westus*'")]
        [InlineData("in", "[ 'eastus' ]")]
        [InlineData("notIn", "[ 'westus' ]")]
        [InlineData("contains", "'eastus'")]
        [InlineData("notContains", "'westus'")]
        [InlineData("containsKey", "'eastus'")]
        [InlineData("notContainsKey", "'westus'")]
        [InlineData("exists", "true")]
        [InlineData("match", "'eastus'")]
        [InlineData("notMatch", "'westus'")]
        [InlineData("greater", "1")]
        [InlineData("greaterOrEquals", "1")]
        [InlineData("less", "1")]
        [InlineData("lessOrEquals", "1")]
        [InlineData("matchInsensitively", "'eastus'")]
        [InlineData("notMatchInsensitively", "'westus'")]
        public void LinterTests_Parsing_LeafConditionOperators(string operatorName, string operatorValue)
        {
            var policy = @"
            {
                'properties': {
                    'displayName': 'Test Policy',
                    'description': 'A policy for testing',
                    'mode': 'Indexed',
                    'parameters': {
                    },
                    'policyRule': {
                        'if': {
                            'field': 'location',
                            '" + operatorName + @"': " + operatorValue + @"

                        },
                        'then': {
                            'effect': '[parameters(\'effect\')]'
                        }
                    }
                }
            }";

            // Parse the policy definition
            var policyDefinitionObject = policy.FromJson<PolicyDefinitionObject>(settings: PolicySerializerSettings.Settings);

            // Create a PolicyDefinition instance from the parsed object
            var mockMetadata = new MockTypeMetadata();
            var policyDefinition = new PolicyDefinition(
                policyDefinitionObject,
                mockMetadata);

            LeafCondition leafCondition = null;

            // Create a visitor to traverse the expression tree
            var visitor = new PolicyExpressionVisitor
            {
                Visit = (expression) =>
                {
                    if (expression is LeafCondition leaf)
                    {
                        if (leafCondition == null)
                        {
                            // Store the leaf condition for verification
                            leafCondition = leaf;
                        }
                        else
                        {
                            throw new Exception("Multiple leaf conditions found, expected only one.");
                        }
                    }
                }
            };

            // Visit all expressions in the policy definition
            policyDefinition.Visit(visitor);

            leafCondition.Should().NotBeNull();
            leafCondition.Operator.Name.Should().Be(operatorName);
        }

        [Fact]
        public void LinterTests_Parsing_InvalidJson()
        {
            var mockMetadata = new MockTypeMetadata();
            var linter = new PolicyLinter(Array.Empty<ILinterRule>(), mockMetadata);

            var result = linter.Lint("[1, 2, 3]"); // Invalid JSON for policy definition

            var expectedOutput = BuiltinLinterOutputs.PolicyDefinitionParsingFailure(parserError: string.Empty);
            result.Should().ContainSingle().Which.Should().BeEquivalentTo(expectedOutput, options => options.Excluding(output => output.Description));
            result.Should().ContainSingle()
                .Which.Description.Should().Contain("Failed to parse the provided policy definition JSON");
        }

        [Fact]
        public void LinterTests_Parsing_MissingProperties()
        {
            var mockMetadata = new MockTypeMetadata();
            var linter = new PolicyLinter(Array.Empty<ILinterRule>(), mockMetadata);

            var result = linter.Lint("{ }"); // Missing "properties" object

            var expectedOutput = BuiltinLinterOutputs.PolicyDefinitionParsingFailure(parserError: string.Empty);
            result.Should().ContainSingle().Which.Should().BeEquivalentTo(expectedOutput, options => options.Excluding(output => output.Description));
            result.Should().ContainSingle()
                .Which.Description.Should().Contain("Failed to parse the provided policy definition JSON. Parsing error: Required property 'properties' not found in JSON. Path '', line 1, position 3.");
        }

        [Fact]
        public void LinterTests_Parsing_MissingPolicyRule()
        {
            var mockMetadata = new MockTypeMetadata();
            var linter = new PolicyLinter(Array.Empty<ILinterRule>(), mockMetadata);

            var result = linter.Lint("{ 'properties': { } }"); // Missing "policyRule" object

            var expectedOutput = BuiltinLinterOutputs.PolicyDefinitionParsingFailure(parserError: string.Empty);
            result.Should().ContainSingle().Which.Should().BeEquivalentTo(expectedOutput, options => options.Excluding(output => output.Description));
            result.Should().ContainSingle()
                .Which.Description.Should().Contain("Failed to parse the provided policy definition JSON. Parsing error: Required property 'policyRule' not found in JSON. Path '', line 1, position 17.");
        }

        [Fact]
        public void LinterTests_Parsing_NotAnObject()
        {
            var mockMetadata = new MockTypeMetadata();
            var linter = new PolicyLinter(Array.Empty<ILinterRule>(), mockMetadata);

            var result = linter.Lint("{ 'properties': { 'policyRule': 'not an object' } }");

            var expectedOutput = BuiltinLinterOutputs.PolicyDefinitionParsingFailure(parserError: string.Empty);
            result.Should().ContainSingle().Which.Should().BeEquivalentTo(expectedOutput, options => options.Excluding(output => output.Description));
            result.Should().ContainSingle()
                .Which.Description.Should().Contain("Failed to parse the provided policy definition JSON.");
        }

        [Fact]
        public void LinterTests_Parsing_MissingIf()
        {
            var mockMetadata = new MockTypeMetadata();
            var linter = new PolicyLinter(Array.Empty<ILinterRule>(), mockMetadata);

            var result = linter.Lint("{ 'properties': { 'policyRule': { 'then': { 'effect': 'deny' } } } }");

            var expectedOutput = BuiltinLinterOutputs.PolicyDefinitionParsingFailure(parserError: string.Empty);
            result.Should().ContainSingle().Which.Should().BeEquivalentTo(expectedOutput, options => options.Excluding(output => output.Description));
            result.Should().ContainSingle()
                .Which.Description.Should().Contain("Failed to parse the provided policy definition JSON.");
        }

        [Fact]
        public void LinterTests_Parsing_IfNotAnObject()
        {
            var mockMetadata = new MockTypeMetadata();
            var linter = new PolicyLinter(Array.Empty<ILinterRule>(), mockMetadata);

            var result = linter.Lint("{ 'properties': { 'policyRule': { 'if': 'not an object', 'then': { 'effect': 'deny' } } } }");

            var expectedOutput = BuiltinLinterOutputs.PolicyDefinitionParsingFailure(parserError: string.Empty);
            result.Should().ContainSingle().Which.Should().BeEquivalentTo(expectedOutput, options => options.Excluding(output => output.Description));
            result.Should().ContainSingle()
                .Which.Description.Should().Contain("Failed to parse the provided policy definition JSON.");
        }

        [Fact]
        public void LinterTests_Parsing_MissingThen()
        {
            var mockMetadata = new MockTypeMetadata();
            var linter = new PolicyLinter(Array.Empty<ILinterRule>(), mockMetadata);

            var result = linter.Lint("{ 'properties': { 'policyRule': { 'if': { 'value': 1, 'equals': 1 } } } }");

            var expectedOutput = BuiltinLinterOutputs.PolicyDefinitionParsingFailure(parserError: string.Empty);
            result.Should().ContainSingle().Which.Should().BeEquivalentTo(expectedOutput, options => options.Excluding(output => output.Description));
            result.Should().ContainSingle()
                .Which.Description.Should().Contain("Failed to parse the provided policy definition JSON.");
        }

        [Fact]
        public void LinterTests_Parsing_ThenNotAnObject()
        {
            var mockMetadata = new MockTypeMetadata();
            var linter = new PolicyLinter(Array.Empty<ILinterRule>(), mockMetadata);

            var result = linter.Lint("{ 'properties': { 'policyRule': { 'if': { 'value': 1, 'equals': 1 }, 'then': 'not an object' } } }");

            var expectedOutput = BuiltinLinterOutputs.PolicyDefinitionParsingFailure(parserError: string.Empty);
            result.Should().ContainSingle().Which.Should().BeEquivalentTo(expectedOutput, options => options.Excluding(output => output.Description));
            result.Should().ContainSingle()
                .Which.Description.Should().Contain("Failed to parse the provided policy definition JSON.");
        }

        [Fact]
        public void LinterTests_Parsing_ThenMissingEffect()
        {
            var mockMetadata = new MockTypeMetadata();
            var linter = new PolicyLinter(Array.Empty<ILinterRule>(), mockMetadata);

            var result = linter.Lint("{ 'properties': { 'policyRule': { 'if': { 'value': 1, 'equals': 1 }, 'then': { } } } }");

            var expectedOutput = BuiltinLinterOutputs.PolicyDefinitionParsingFailure(parserError: string.Empty);
            result.Should().ContainSingle().Which.Should().BeEquivalentTo(expectedOutput, options => options.Excluding(output => output.Description));
            result.Should().ContainSingle()
                .Which.Description.Should().Contain("Failed to parse the provided policy definition JSON.");
        }

        [Fact]
        public void LinterTests_Parsing_InputIsPolicyDefinitionPropertyBag()
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


            var result = linter.Lint(@"{ 'mode': 'Indexed', 'policyRule': { 'if': { 'value': 1, 'equals': 1 }, 'then': { 'effect': 'deny' } } }");
            result.Should().HaveCount(2);

            result.Should().Contain(output => output.Title == "Linter Input Is Policy Definition Property Bag");
            result.Should().Contain(output => output.Description == "Test rule was invoked");
        }

        [Fact]
        public void LinterTests_Parsing_FailureToParsePolicyRule()
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

            var result = linter.Lint("{ 'properties': { 'policyRule': 'not an object' } }");
            result.Should().HaveCount(1);
            result[0].Severity.Should().Be(Severity.Critical);
            result[0].Category.Should().Be(Category.Parsing);
            result[0].Description.Should().Contain("Failed to parse the provided policy definition JSON. Parsing error: Error converting value \"not an object\" to type 'Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Parsing.PolicyRuleObject'. Path '', line 1, position 47.");
        }
    }
}
