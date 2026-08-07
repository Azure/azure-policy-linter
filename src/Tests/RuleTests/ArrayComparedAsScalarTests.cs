// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Newtonsoft.Json.Linq;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="ArrayComparedAsScalar"/> rule.
    /// </summary>
    public class ArrayComparedAsScalarTests
    {
        private const string ArrayAlias = "Microsoft.Test/widgets/arrayProperty";
        private const string ArrayAliasWithAbsentVersions = "Microsoft.Test/widgets/arrayPropertyWithAbsentVersions";
        private const string ArraySelectorAlias = "Microsoft.Test/widgets/arrayProperty[*]";
        private const string ScalarAlias = "Microsoft.Test/widgets/scalarProperty";
        private const string MixedTypeAlias = "Microsoft.Test/widgets/mixedTypeProperty";
        private const string AbsentAlias = "Microsoft.Test/widgets/absentProperty";
        private const string EmptyMetadataAlias = "Microsoft.Test/widgets/emptyMetadataProperty";
        private const string EmptyTypeAlias = "Microsoft.Test/widgets/emptyTypeProperty";
        private const string AnyTypeAlias = "Microsoft.Test/widgets/anyTypeProperty";
        private const string NotSpecifiedTypeAlias = "Microsoft.Test/widgets/notSpecifiedTypeProperty";

        private static readonly ITypeMetadata TypeMetadata = new TestTypeMetadata();
        private static readonly ITypeMetadata RealTypeMetadata = new TypeMetadata(
            metadataProvider: new OfflineMetadataProvider(),
            aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_ArrayComparedAsScalar_Equals()
        {
            var linter = ArrayComparedAsScalarTests.CreateLinter();
            var policyDefinition = ArrayComparedAsScalarTests.CreatePolicy(
                alias: ArrayComparedAsScalarTests.ArrayAlias,
                operatorName: "equals",
                operatorValue: @"""ready""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "array-compared-as-scalar",
                Title: "Array Compared as Scalar",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 71,
                Path: "properties.policyRule.if.field",
                Description: "The field alias: 'Microsoft.Test/widgets/arrayProperty' refers to an entire array, so comparing it with 'equals' is an invalid comparison that always evaluates to false. Use a field count expression to apply the condition to the array members, or remove the condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("notEquals", @"""item-#""")]
        [InlineData("like", @"""item-*""")]
        [InlineData("notLike", @"""item-*""")]
        [InlineData("match", @"""item-#""")]
        [InlineData("notMatch", @"""item-#""")]
        [InlineData("matchInsensitively", @"""item-#""")]
        [InlineData("notMatchInsensitively", @"""item-#""")]
        [InlineData("greater", "5")]
        [InlineData("less", "5")]
        [InlineData("lessOrEquals", "5.5")]
        [InlineData("greaterOrEquals", "true")]
        public void RuleTests_ArrayComparedAsScalar_MatchOrOrdering(string operatorName, string operatorValue)
        {
            var linter = ArrayComparedAsScalarTests.CreateLinter();
            var policyDefinition = ArrayComparedAsScalarTests.CreatePolicy(
                alias: ArrayComparedAsScalarTests.ArrayAlias,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "array-compared-as-scalar",
                Title: "Array Compared as Scalar",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 71,
                Path: "properties.policyRule.if.field",
                Description: $"The field alias: 'Microsoft.Test/widgets/arrayProperty' refers to an entire array, so comparing it with '{operatorName}' is an invalid comparison that always evaluates to false. Use a field count expression to apply the condition to the array members, or remove the condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_ArrayComparedAsScalar_RealNsgArrayAlias()
        {
            const string alias = "Microsoft.Network/networkSecurityGroups/securityRules";
            var linter = ArrayComparedAsScalarTests.CreateLinter(
                metadata: ArrayComparedAsScalarTests.RealTypeMetadata);
            var policyDefinition = ArrayComparedAsScalarTests.CreatePolicy(
                alias: alias,
                operatorName: "equals",
                operatorValue: @"""ready""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "array-compared-as-scalar",
                Title: "Array Compared as Scalar",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 88,
                Path: "properties.policyRule.if.field",
                Description: $"The field alias: '{alias}' refers to an entire array, so comparing it with 'equals' is an invalid comparison that always evaluates to false. Use a field count expression to apply the condition to the array members, or remove the condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_ArrayComparedAsScalar_MixedCasingAndAbsentVersions()
        {
            var linter = ArrayComparedAsScalarTests.CreateLinter();
            var policyDefinition = ArrayComparedAsScalarTests.CreatePolicy(
                alias: "microsoft.test/WIDGETS/arraypropertywithabsentversions",
                operatorName: "EqUaLs",
                operatorValue: "true");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "array-compared-as-scalar",
                Title: "Array Compared as Scalar",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 89,
                Path: "properties.policyRule.if.field",
                Description: "The field alias: 'microsoft.test/WIDGETS/arraypropertywithabsentversions' refers to an entire array, so comparing it with 'equals' is an invalid comparison that always evaluates to false. Use a field count expression to apply the condition to the array members, or remove the condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData(ArraySelectorAlias)]
        [InlineData(ScalarAlias)]
        [InlineData(MixedTypeAlias)]
        [InlineData(AbsentAlias)]
        [InlineData(EmptyMetadataAlias)]
        [InlineData(EmptyTypeAlias)]
        [InlineData(AnyTypeAlias)]
        [InlineData(NotSpecifiedTypeAlias)]
        public void RuleTests_ArrayComparedAsScalar_NonArrayOrInsufficientMetadata(string alias)
        {
            var linter = ArrayComparedAsScalarTests.CreateLinter();
            var policyDefinition = ArrayComparedAsScalarTests.CreatePolicy(
                alias: alias,
                operatorName: "equals",
                operatorValue: @"""ready""");

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("contains", @"""ready""")]
        [InlineData("notContains", @"""ready""")]
        [InlineData("in", @"[""ready""]")]
        [InlineData("notIn", @"[""ready""]")]
        [InlineData("containsKey", @"""name""")]
        [InlineData("notContainsKey", @"""name""")]
        [InlineData("exists", "true")]
        public void RuleTests_ArrayComparedAsScalar_ExcludedOperator(string operatorName, string operatorValue)
        {
            var linter = ArrayComparedAsScalarTests.CreateLinter();
            var policyDefinition = ArrayComparedAsScalarTests.CreatePolicy(
                alias: ArrayComparedAsScalarTests.ArrayAlias,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ArrayComparedAsScalar_TemplateOperand()
        {
            var linter = ArrayComparedAsScalarTests.CreateLinter();
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""target"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Test/widgets/arrayProperty"",
                        ""equals"": ""[parameters('target')]""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData(@"[""ready""]")]
        [InlineData(@"{""state"":""ready""}")]
        public void RuleTests_ArrayComparedAsScalar_NonScalarOperand(string operatorValue)
        {
            var linter = ArrayComparedAsScalarTests.CreateLinter();
            var policyDefinition = ArrayComparedAsScalarTests.CreatePolicy(
                alias: ArrayComparedAsScalarTests.ArrayAlias,
                operatorName: "greater",
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ArrayComparedAsScalar_NullOperand()
        {
            var parent = new TestPolicyExpression();
            var condition = new GenericObjectProperty<ConditionObject>
            {
                Value = new ConditionObject
                {
                    Field = new GenericObjectProperty<string>
                    {
                        Value = ArrayComparedAsScalarTests.ArrayAlias,
                    },
                    Greater = new GenericObjectProperty<JToken>
                    {
                        Value = JValue.CreateNull(),
                    },
                },
            };
            var expression = new LeafCondition(
                leafConditionProperty: condition,
                parentPath: ImmutableArray<string>.Empty,
                parent: parent,
                countExpressionScopes: new Stack<CountExpressionScope>(),
                typeMetadata: ArrayComparedAsScalarTests.TypeMetadata);
            var rule = (ILinterRule)new ArrayComparedAsScalar();

            var results = rule.Evaluate(
                expression: expression,
                context: new LinterContext(resourceTypeMetadata: ArrayComparedAsScalarTests.TypeMetadata));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ArrayComparedAsScalar_UnresolvedOrDynamicFieldAccessor()
        {
            var linter = ArrayComparedAsScalarTests.CreateLinter();
            var unresolvedPolicyDefinition = ArrayComparedAsScalarTests.CreatePolicy(
                alias: "Microsoft.Test/widgets/unresolvedProperty",
                operatorName: "equals",
                operatorValue: @"""ready""");
            var dynamicPolicyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""fieldAlias"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""[parameters('fieldAlias')]"",
                        ""equals"": ""ready""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var unresolvedResults = linter.Lint(unresolvedPolicyDefinition);
            var dynamicResults = linter.Lint(dynamicPolicyDefinition);

            unresolvedResults.Should().BeEmpty();
            dynamicResults.Should().BeEmpty();
        }

        private static PolicyLinter CreateLinter()
        {
            return ArrayComparedAsScalarTests.CreateLinter(
                metadata: ArrayComparedAsScalarTests.TypeMetadata);
        }

        private static PolicyLinter CreateLinter(ITypeMetadata metadata)
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ArrayComparedAsScalar(),
                },
                metadata: metadata);
        }

        private static string CreatePolicy(string alias, string operatorName, string operatorValue)
        {
            return $@"
                {{
                  ""properties"": {{
                    ""mode"": ""Indexed"",
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""{alias}"",
                        ""{operatorName}"": {operatorValue}
                      }},
                      ""then"": {{
                        ""effect"": ""audit""
                      }}
                    }}
                  }}
                }}";
        }

        private sealed class TestTypeMetadata : ITypeMetadata
        {
            /// <inheritdoc/>
            public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
            {
                if (string.Equals(aliasName, ArrayComparedAsScalarTests.ArrayAlias, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(aliasName, ArrayComparedAsScalarTests.ArraySelectorAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ArrayComparedAsScalarTests.CreateMetadata(exists: true, type: "Array"),
                    };
                    return true;
                }

                if (string.Equals(aliasName, ArrayComparedAsScalarTests.ArrayAliasWithAbsentVersions, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ArrayComparedAsScalarTests.CreateMetadata(exists: false, type: string.Empty),
                        ArrayComparedAsScalarTests.CreateMetadata(exists: true, type: "aRrAy"),
                        ArrayComparedAsScalarTests.CreateMetadata(exists: true, type: "ARRAY"),
                    };
                    return true;
                }

                if (string.Equals(aliasName, ArrayComparedAsScalarTests.ScalarAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ArrayComparedAsScalarTests.CreateMetadata(exists: true, type: "String"),
                    };
                    return true;
                }

                if (string.Equals(aliasName, ArrayComparedAsScalarTests.MixedTypeAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ArrayComparedAsScalarTests.CreateMetadata(exists: true, type: "Array"),
                        ArrayComparedAsScalarTests.CreateMetadata(exists: true, type: "String"),
                    };
                    return true;
                }

                if (string.Equals(aliasName, ArrayComparedAsScalarTests.AbsentAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ArrayComparedAsScalarTests.CreateMetadata(exists: false, type: string.Empty),
                    };
                    return true;
                }

                if (string.Equals(aliasName, ArrayComparedAsScalarTests.EmptyMetadataAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = Array.Empty<ResourcePropertyMetadata>();
                    return true;
                }

                if (string.Equals(aliasName, ArrayComparedAsScalarTests.EmptyTypeAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ArrayComparedAsScalarTests.CreateMetadata(exists: true, type: string.Empty),
                    };
                    return true;
                }

                if (string.Equals(aliasName, ArrayComparedAsScalarTests.AnyTypeAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ArrayComparedAsScalarTests.CreateMetadata(exists: true, type: "Any"),
                    };
                    return true;
                }

                if (string.Equals(aliasName, ArrayComparedAsScalarTests.NotSpecifiedTypeAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ArrayComparedAsScalarTests.CreateMetadata(exists: true, type: "NotSpecified"),
                    };
                    return true;
                }

                result = Array.Empty<ResourcePropertyMetadata>();
                return false;
            }
        }

        private sealed class TestPolicyExpression : PolicyExpression
        {
            public TestPolicyExpression() : base(
                lineNumber: null,
                linePosition: null,
                path: ImmutableArray<string>.Empty,
                parent: null)
            {
            }

            /// <inheritdoc/>
            public override void Visit(PolicyExpressionVisitor visitor)
            {
            }
        }

        private static ResourcePropertyMetadata CreateMetadata(bool exists, string type)
        {
            return new ResourcePropertyMetadata
            {
                ResourceType = "Microsoft.Test/widgets",
                Exists = exists,
                Type = type,
            };
        }
    }
}
