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
    /// Tests for the <see cref="BareArrayFieldComparedAsScalar"/> rule.
    /// </summary>
    public class BareArrayFieldComparedAsScalarTests
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
        public void RuleTests_BareArrayFieldComparedAsScalar_Equals()
        {
            var linter = BareArrayFieldComparedAsScalarTests.CreateLinter();
            var policyDefinition = BareArrayFieldComparedAsScalarTests.CreatePolicy(
                alias: BareArrayFieldComparedAsScalarTests.ArrayAlias,
                operatorName: "equals",
                operatorValue: @"""ready""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "bare-array-field-compared-as-scalar",
                Title: "Bare Array Field Compared as Scalar",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 71,
                Path: "properties.policyRule.if.field",
                Description: "The field alias: 'Microsoft.Test/widgets/arrayProperty' resolves to the whole array and is used with the scalar comparison operator 'equals'. Use a '[*]' alias or field count to compare array members, or use 'exists' to check whether the property is present.");

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
        public void RuleTests_BareArrayFieldComparedAsScalar_MatchOrOrdering(string operatorName, string operatorValue)
        {
            var linter = BareArrayFieldComparedAsScalarTests.CreateLinter();
            var policyDefinition = BareArrayFieldComparedAsScalarTests.CreatePolicy(
                alias: BareArrayFieldComparedAsScalarTests.ArrayAlias,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "bare-array-field-compared-as-scalar",
                Title: "Bare Array Field Compared as Scalar",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 71,
                Path: "properties.policyRule.if.field",
                Description: $"The field alias: 'Microsoft.Test/widgets/arrayProperty' resolves to the whole array and is used with the scalar comparison operator '{operatorName}'. Use a '[*]' alias or field count to compare array members, or use 'exists' to check whether the property is present.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_BareArrayFieldComparedAsScalar_RealNsgArrayAlias()
        {
            const string alias = "Microsoft.Network/networkSecurityGroups/securityRules";
            var linter = BareArrayFieldComparedAsScalarTests.CreateLinter(
                metadata: BareArrayFieldComparedAsScalarTests.RealTypeMetadata);
            var policyDefinition = BareArrayFieldComparedAsScalarTests.CreatePolicy(
                alias: alias,
                operatorName: "equals",
                operatorValue: @"""ready""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "bare-array-field-compared-as-scalar",
                Title: "Bare Array Field Compared as Scalar",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 88,
                Path: "properties.policyRule.if.field",
                Description: $"The field alias: '{alias}' resolves to the whole array and is used with the scalar comparison operator 'equals'. Use a '[*]' alias or field count to compare array members, or use 'exists' to check whether the property is present.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_BareArrayFieldComparedAsScalar_MixedCasingAndAbsentVersions()
        {
            var linter = BareArrayFieldComparedAsScalarTests.CreateLinter();
            var policyDefinition = BareArrayFieldComparedAsScalarTests.CreatePolicy(
                alias: "microsoft.test/WIDGETS/arraypropertywithabsentversions",
                operatorName: "EqUaLs",
                operatorValue: "true");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "bare-array-field-compared-as-scalar",
                Title: "Bare Array Field Compared as Scalar",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 89,
                Path: "properties.policyRule.if.field",
                Description: "The field alias: 'microsoft.test/WIDGETS/arraypropertywithabsentversions' resolves to the whole array and is used with the scalar comparison operator 'equals'. Use a '[*]' alias or field count to compare array members, or use 'exists' to check whether the property is present.");

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
        public void RuleTests_BareArrayFieldComparedAsScalar_NonArrayOrInsufficientMetadata(string alias)
        {
            var linter = BareArrayFieldComparedAsScalarTests.CreateLinter();
            var policyDefinition = BareArrayFieldComparedAsScalarTests.CreatePolicy(
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
        public void RuleTests_BareArrayFieldComparedAsScalar_ExcludedOperator(string operatorName, string operatorValue)
        {
            var linter = BareArrayFieldComparedAsScalarTests.CreateLinter();
            var policyDefinition = BareArrayFieldComparedAsScalarTests.CreatePolicy(
                alias: BareArrayFieldComparedAsScalarTests.ArrayAlias,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BareArrayFieldComparedAsScalar_TemplateOperand()
        {
            var linter = BareArrayFieldComparedAsScalarTests.CreateLinter();
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
        public void RuleTests_BareArrayFieldComparedAsScalar_NonScalarOperand(string operatorValue)
        {
            var linter = BareArrayFieldComparedAsScalarTests.CreateLinter();
            var policyDefinition = BareArrayFieldComparedAsScalarTests.CreatePolicy(
                alias: BareArrayFieldComparedAsScalarTests.ArrayAlias,
                operatorName: "greater",
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BareArrayFieldComparedAsScalar_NullOperand()
        {
            var parent = new TestPolicyExpression();
            var condition = new GenericObjectProperty<ConditionObject>
            {
                Value = new ConditionObject
                {
                    Field = new GenericObjectProperty<string>
                    {
                        Value = BareArrayFieldComparedAsScalarTests.ArrayAlias,
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
                typeMetadata: BareArrayFieldComparedAsScalarTests.TypeMetadata);
            var rule = (ILinterRule)new BareArrayFieldComparedAsScalar();

            var results = rule.Evaluate(
                expression: expression,
                context: new LinterContext(resourceTypeMetadata: BareArrayFieldComparedAsScalarTests.TypeMetadata));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_BareArrayFieldComparedAsScalar_UnresolvedOrDynamicFieldAccessor()
        {
            var linter = BareArrayFieldComparedAsScalarTests.CreateLinter();
            var unresolvedPolicyDefinition = BareArrayFieldComparedAsScalarTests.CreatePolicy(
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
            return BareArrayFieldComparedAsScalarTests.CreateLinter(
                metadata: BareArrayFieldComparedAsScalarTests.TypeMetadata);
        }

        private static PolicyLinter CreateLinter(ITypeMetadata metadata)
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new BareArrayFieldComparedAsScalar(),
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
                if (string.Equals(aliasName, BareArrayFieldComparedAsScalarTests.ArrayAlias, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(aliasName, BareArrayFieldComparedAsScalarTests.ArraySelectorAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: true, type: "Array"),
                    };
                    return true;
                }

                if (string.Equals(aliasName, BareArrayFieldComparedAsScalarTests.ArrayAliasWithAbsentVersions, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: false, type: string.Empty),
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: true, type: "aRrAy"),
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: true, type: "ARRAY"),
                    };
                    return true;
                }

                if (string.Equals(aliasName, BareArrayFieldComparedAsScalarTests.ScalarAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: true, type: "String"),
                    };
                    return true;
                }

                if (string.Equals(aliasName, BareArrayFieldComparedAsScalarTests.MixedTypeAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: true, type: "Array"),
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: true, type: "String"),
                    };
                    return true;
                }

                if (string.Equals(aliasName, BareArrayFieldComparedAsScalarTests.AbsentAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: false, type: string.Empty),
                    };
                    return true;
                }

                if (string.Equals(aliasName, BareArrayFieldComparedAsScalarTests.EmptyMetadataAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = Array.Empty<ResourcePropertyMetadata>();
                    return true;
                }

                if (string.Equals(aliasName, BareArrayFieldComparedAsScalarTests.EmptyTypeAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: true, type: string.Empty),
                    };
                    return true;
                }

                if (string.Equals(aliasName, BareArrayFieldComparedAsScalarTests.AnyTypeAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: true, type: "Any"),
                    };
                    return true;
                }

                if (string.Equals(aliasName, BareArrayFieldComparedAsScalarTests.NotSpecifiedTypeAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        BareArrayFieldComparedAsScalarTests.CreateMetadata(exists: true, type: "NotSpecified"),
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
