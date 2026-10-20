// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using System.Collections.Immutable;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="ObjectComparedAsScalar"/> rule.
    /// </summary>
    public class ObjectComparedAsScalarTests
    {
        private const string ObjectAlias = "Microsoft.Test/widgets/objectProperty";
        private const string ObjectAliasWithUnknownVersions = "Microsoft.Test/widgets/objectPropertyWithUnknownVersions";
        private const string ObjectArrayMemberAlias = "Microsoft.Test/widgets/objects[*]";
        private const string MixedTypeAlias = "Microsoft.Test/widgets/mixedTypeProperty";
        private const string ArrayAlias = "Microsoft.Test/widgets/arrayProperty";
        private const string ScalarAlias = "Microsoft.Test/widgets/scalarProperty";
        private const string UnknownAlias = "Microsoft.Test/widgets/unknownProperty";
        private const string AbsentAlias = "Microsoft.Test/widgets/absentProperty";

        private static readonly ITypeMetadata TypeMetadata = new TestTypeMetadata();
        private static readonly ITypeMetadata RealTypeMetadata = new TypeMetadata(
            metadataProvider: new OfflineMetadataProvider(),
            aliasResolver: new AliasResolver());

        [Theory]
        [InlineData(ObjectComparedAsScalarTests.ObjectAlias, "equals")]
        [InlineData(ObjectComparedAsScalarTests.ObjectAlias, "notEquals")]
        [InlineData(ObjectComparedAsScalarTests.ObjectAliasWithUnknownVersions, "eQuAlS")]
        [InlineData(ObjectComparedAsScalarTests.ObjectArrayMemberAlias, "nOtEqUaLs")]
        public void RuleTests_ObjectComparedAsScalar_ObjectField(string alias, string operatorName)
        {
            var linter = ObjectComparedAsScalarTests.CreateLinter();
            var policyDefinition = ObjectComparedAsScalarTests.CreatePolicy(
                alias: alias,
                operatorName: operatorName,
                operatorValue: @"""value""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var expectedOperator = operatorName.Equals("notEquals", StringComparison.OrdinalIgnoreCase)
                ? "notEquals"
                : "equals";
            var output = new LinterOutput(
                RuleIdentifier: "object-compared-as-scalar",
                Title: "Object Compared as Scalar",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 6,
                LinePosition: 35 + alias.Length,
                Path: "properties.policyRule.if.field",
                Description: $"The field alias: '{alias}' refers to an object. The '{expectedOperator}' condition does not compare the object's contents, so its result is independent of the object's properties. Reference a property alias or use a 'value' expression for complete-object equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_ObjectComparedAsScalar_RealObjectAlias()
        {
            const string alias = "Microsoft.Automation/automationAccounts/encryption.keyVaultProperties";
            var linter = ObjectComparedAsScalarTests.CreateLinter(metadata: ObjectComparedAsScalarTests.RealTypeMetadata);
            var policyDefinition = ObjectComparedAsScalarTests.CreatePolicy(
                alias: alias,
                operatorName: "equals",
                operatorValue: @"""my-key""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
        }

        [Theory]
        [InlineData(ObjectComparedAsScalarTests.MixedTypeAlias)]
        [InlineData(ObjectComparedAsScalarTests.ArrayAlias)]
        [InlineData(ObjectComparedAsScalarTests.ScalarAlias)]
        [InlineData(ObjectComparedAsScalarTests.UnknownAlias)]
        [InlineData(ObjectComparedAsScalarTests.AbsentAlias)]
        public void RuleTests_ObjectComparedAsScalar_NonObjectOrInsufficientMetadata(string alias)
        {
            var linter = ObjectComparedAsScalarTests.CreateLinter();
            var policyDefinition = ObjectComparedAsScalarTests.CreatePolicy(
                alias: alias,
                operatorName: "equals",
                operatorValue: @"""value""");

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("exists", "true")]
        [InlineData("contains", @"""value""")]
        [InlineData("greater", "5")]
        public void RuleTests_ObjectComparedAsScalar_OtherOperator(string operatorName, string operatorValue)
        {
            var linter = ObjectComparedAsScalarTests.CreateLinter();
            var policyDefinition = ObjectComparedAsScalarTests.CreatePolicy(
                alias: ObjectComparedAsScalarTests.ObjectAlias,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ObjectComparedAsScalar_ParameterizedValue()
        {
            var linter = ObjectComparedAsScalarTests.CreateLinter();
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""parameters"": {
                      ""value"": { ""type"": ""String"" }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Test/widgets/objectProperty"",
                        ""equals"": ""[parameters('value')]""
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

        [Fact]
        public void RuleTests_ObjectComparedAsScalar_DynamicField()
        {
            var linter = ObjectComparedAsScalarTests.CreateLinter();
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""parameters"": {
                      ""fieldAlias"": { ""type"": ""String"" }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""[parameters('fieldAlias')]"",
                        ""equals"": ""value""
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

        private static PolicyLinter CreateLinter()
        {
            return ObjectComparedAsScalarTests.CreateLinter(metadata: ObjectComparedAsScalarTests.TypeMetadata);
        }

        private static PolicyLinter CreateLinter(ITypeMetadata metadata)
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ObjectComparedAsScalar(),
                },
                metadata: metadata);
        }

        private static string CreatePolicy(string alias, string operatorName, string operatorValue)
        {
            return $@"
                {{
                  ""properties"": {{
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

        private static ResourcePropertyMetadata CreateMetadata(bool exists, string type)
        {
            return new ResourcePropertyMetadata
            {
                ResourceType = "Microsoft.Test/widgets",
                ApiVersions = ImmutableArray.Create("2024-01-01"),
                Path = "properties.value",
                Type = type,
                Exists = exists,
            };
        }

        private sealed class TestTypeMetadata : ITypeMetadata
        {
            /// <inheritdoc/>
            public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
            {
                if (aliasName.Equals(ObjectComparedAsScalarTests.ObjectAlias, StringComparison.OrdinalIgnoreCase) ||
                    aliasName.Equals(ObjectComparedAsScalarTests.ObjectArrayMemberAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: "Object"),
                    };
                    return true;
                }

                if (aliasName.Equals(ObjectComparedAsScalarTests.ObjectAliasWithUnknownVersions, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: string.Empty),
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: "NotSpecified"),
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: "Any"),
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: "oBjEcT"),
                    };
                    return true;
                }

                if (aliasName.Equals(ObjectComparedAsScalarTests.MixedTypeAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: "Object"),
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: "String"),
                    };
                    return true;
                }

                if (aliasName.Equals(ObjectComparedAsScalarTests.ArrayAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: "Array"),
                    };
                    return true;
                }

                if (aliasName.Equals(ObjectComparedAsScalarTests.ScalarAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: "String"),
                    };
                    return true;
                }

                if (aliasName.Equals(ObjectComparedAsScalarTests.UnknownAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: string.Empty),
                        ObjectComparedAsScalarTests.CreateMetadata(exists: true, type: "Any"),
                    };
                    return true;
                }

                if (aliasName.Equals(ObjectComparedAsScalarTests.AbsentAlias, StringComparison.OrdinalIgnoreCase))
                {
                    result = new[]
                    {
                        ObjectComparedAsScalarTests.CreateMetadata(exists: false, type: "Object"),
                    };
                    return true;
                }

                result = Array.Empty<ResourcePropertyMetadata>();
                return false;
            }

            /// <inheritdoc/>
            public bool TryGetResourceTypeCapabilities(string resourceType, out ResourceTypeCapabilities result)
            {
                result = ResourceTypeCapabilities.None;
                return false;
            }
        }
    }
}
