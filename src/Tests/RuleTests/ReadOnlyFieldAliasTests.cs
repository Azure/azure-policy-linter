namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="ReadOnlyFieldAlias"/> rule.
    /// </summary>
    public class ReadOnlyFieldAliasTests
    {
        private const string FindingDescription = "The field alias: 'Microsoft.Storage/storageAccounts/privateEndpointConnections' maps to a property that is marked as read-only in one or more API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2019-06-01, 2020-08-01-preview, 2021-01-01, 2021-02-01, 2021-04-01, 2021-06-01, 2021-08-01, 2021-09-01, 2022-05-01, 2022-09-01, 2023-01-01, 2023-04-01, 2023-05-01, 2024-01-01, 2025-01-01, 2025-06-01, 2025-08-01, 2026-04-01'";

        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        /// <summary>
        /// Verifies that a literal audit effect produces an informational finding.
        /// </summary>
        /// <param name="effect">The policy effect.</param>
        [Theory]
        [InlineData("audit")]
        [InlineData("AuDiTiFnOtExIsTs")]
        public void RuleTests_ReadOnlyFieldAlias_LiteralAuditEffect_ShouldBeInformational(string effect)
        {
            var policyDefinition = ReadOnlyFieldAliasTests.CreatePolicy(
                parameters: null,
                effect: $@"""{effect}""");

            ReadOnlyFieldAliasTests.AssertFinding(
                policyDefinition: policyDefinition,
                expectedSeverity: Severity.Informational);
        }

        /// <summary>
        /// Verifies that a literal deny effect produces a warning finding.
        /// </summary>
        [Fact]
        public void RuleTests_ReadOnlyFieldAlias_ReadOnlyAlias_ShouldFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ReadOnlyFieldAlias()
                },
                metadata: ReadOnlyFieldAliasTests.TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/privateEndpointConnections"",
                            ""equals"": ""Something""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    } 
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "read-only-field-alias",
                Title: "Read-Only Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 99,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: ReadOnlyFieldAliasTests.FindingDescription);

            results.Should().ContainEquivalentOf(output);
        }

        /// <summary>
        /// Verifies that an audit-only string effect parameter produces an informational finding.
        /// </summary>
        [Fact]
        public void RuleTests_ReadOnlyFieldAlias_AuditOnlyEffectParameter_ShouldBeInformational()
        {
            var parameters = ReadOnlyFieldAliasTests.CreateEffectParameter(
                type: "String",
                defaultValue: "AUDIT",
                allowedValues: @"[""AUDIT"", ""AuditIfNotExists""]");
            var policyDefinition = ReadOnlyFieldAliasTests.CreatePolicy(
                parameters: parameters,
                effect: @"""[parameters('effect')]""");

            ReadOnlyFieldAliasTests.AssertFinding(
                policyDefinition: policyDefinition,
                expectedSeverity: Severity.Informational);
        }

        /// <summary>
        /// Verifies that an audit-only string effect parameter without a default produces an informational finding.
        /// </summary>
        [Fact]
        public void RuleTests_ReadOnlyFieldAlias_AuditOnlyEffectParameterWithoutDefault_ShouldBeInformational()
        {
            var parameters = ReadOnlyFieldAliasTests.CreateEffectParameter(
                type: "String",
                defaultValue: null,
                allowedValues: @"[""audit"", ""auditIfNotExists""]");
            var policyDefinition = ReadOnlyFieldAliasTests.CreatePolicy(
                parameters: parameters,
                effect: @"""[parameters('effect')]""");

            ReadOnlyFieldAliasTests.AssertFinding(
                policyDefinition: policyDefinition,
                expectedSeverity: Severity.Informational);
        }

        /// <summary>
        /// Verifies that a case-mismatched default produces a warning finding.
        /// </summary>
        [Fact]
        public void RuleTests_ReadOnlyFieldAlias_CaseMismatchedDefault_ShouldBeWarning()
        {
            var parameters = ReadOnlyFieldAliasTests.CreateEffectParameter(
                type: "String",
                defaultValue: "aUdIt",
                allowedValues: @"[""AUDIT"", ""AuditIfNotExists""]");
            var policyDefinition = ReadOnlyFieldAliasTests.CreatePolicy(
                parameters: parameters,
                effect: @"""[parameters('effect')]""");

            ReadOnlyFieldAliasTests.AssertFinding(
                policyDefinition: policyDefinition,
                expectedSeverity: Severity.Warning);
        }

        /// <summary>
        /// Verifies that mixed audit and enforcement allowed values produce a warning finding.
        /// </summary>
        [Fact]
        public void RuleTests_ReadOnlyFieldAlias_MixedEffectParameter_ShouldBeWarning()
        {
            var parameters = ReadOnlyFieldAliasTests.CreateEffectParameter(
                type: "String",
                defaultValue: "audit",
                allowedValues: @"[""audit"", ""deny""]");
            var policyDefinition = ReadOnlyFieldAliasTests.CreatePolicy(
                parameters: parameters,
                effect: @"""[parameters('effect')]""");

            ReadOnlyFieldAliasTests.AssertFinding(
                policyDefinition: policyDefinition,
                expectedSeverity: Severity.Warning);
        }

        /// <summary>
        /// Verifies that unconstrained audit-default parameters produce warning findings.
        /// </summary>
        /// <param name="allowedValues">The allowed values JSON.</param>
        [Theory]
        [InlineData(null)]
        [InlineData("[]")]
        public void RuleTests_ReadOnlyFieldAlias_UnconstrainedEffectParameter_ShouldBeWarning(string allowedValues)
        {
            var parameters = ReadOnlyFieldAliasTests.CreateEffectParameter(
                type: "String",
                defaultValue: "audit",
                allowedValues: allowedValues);
            var policyDefinition = ReadOnlyFieldAliasTests.CreatePolicy(
                parameters: parameters,
                effect: @"""[parameters('effect')]""");

            ReadOnlyFieldAliasTests.AssertFinding(
                policyDefinition: policyDefinition,
                expectedSeverity: Severity.Warning);
        }

        /// <summary>
        /// Verifies that a default outside audit-only allowed values produces a warning finding.
        /// </summary>
        [Fact]
        public void RuleTests_ReadOnlyFieldAlias_DefaultOutsideAllowedValues_ShouldBeWarning()
        {
            var parameters = ReadOnlyFieldAliasTests.CreateEffectParameter(
                type: "String",
                defaultValue: "deny",
                allowedValues: @"[""audit"", ""auditIfNotExists""]");
            var policyDefinition = ReadOnlyFieldAliasTests.CreatePolicy(
                parameters: parameters,
                effect: @"""[parameters('effect')]""");

            ReadOnlyFieldAliasTests.AssertFinding(
                policyDefinition: policyDefinition,
                expectedSeverity: Severity.Warning);
        }

        /// <summary>
        /// Verifies that non-audit literal effects produce warning findings.
        /// </summary>
        /// <param name="effect">The policy effect.</param>
        [Theory]
        [InlineData("disabled")]
        [InlineData("manual")]
        [InlineData("auditAction")]
        [InlineData("unknown")]
        public void RuleTests_ReadOnlyFieldAlias_NonAuditLiteralEffect_ShouldBeWarning(string effect)
        {
            var policyDefinition = ReadOnlyFieldAliasTests.CreatePolicy(
                parameters: null,
                effect: $@"""{effect}""");

            ReadOnlyFieldAliasTests.AssertFinding(
                policyDefinition: policyDefinition,
                expectedSeverity: Severity.Warning);
        }

        /// <summary>
        /// Verifies that a complex effect expression produces a warning finding.
        /// </summary>
        [Fact]
        public void RuleTests_ReadOnlyFieldAlias_ComplexEffectExpression_ShouldBeWarning()
        {
            var policyDefinition = ReadOnlyFieldAliasTests.CreatePolicy(
                parameters: null,
                effect: @"""[concat('au', 'dit')]""");

            ReadOnlyFieldAliasTests.AssertFinding(
                policyDefinition: policyDefinition,
                expectedSeverity: Severity.Warning);
        }

        /// <summary>
        /// Verifies that unresolved and non-string effect parameters produce warning findings.
        /// </summary>
        /// <param name="parameters">The parameter definitions.</param>
        [Theory]
        [InlineData(null)]
        [InlineData(@"""effect"": { ""type"": ""Integer"", ""defaultValue"": 1, ""allowedValues"": [1] }")]
        public void RuleTests_ReadOnlyFieldAlias_UnresolvedOrNonStringEffectParameter_ShouldBeWarning(string parameters)
        {
            var policyDefinition = ReadOnlyFieldAliasTests.CreatePolicy(
                parameters: parameters,
                effect: @"""[parameters('effect')]""");

            ReadOnlyFieldAliasTests.AssertFinding(
                policyDefinition: policyDefinition,
                expectedSeverity: Severity.Warning);
        }

        /// <summary>
        /// Verifies that writable aliases do not produce findings.
        /// </summary>
        [Fact]
        public void RuleTests_ReadOnlyFieldAlias_WritableAlias_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ReadOnlyFieldAlias()
                },
                metadata: ReadOnlyFieldAliasTests.TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"",
                            ""equals"": ""Something""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    } 
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        /// <summary>
        /// Asserts a read-only alias finding.
        /// </summary>
        /// <param name="policyDefinition">The policy definition.</param>
        /// <param name="expectedSeverity">The expected severity.</param>
        private static void AssertFinding(string policyDefinition, Severity expectedSeverity)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ReadOnlyFieldAlias()
                },
                metadata: ReadOnlyFieldAliasTests.TypeMetadata);

            var result = linter.Lint(policyDefinition).Should().ContainSingle().Subject;

            result.RuleIdentifier.Should().Be("read-only-field-alias");
            result.Title.Should().Be("Read-Only Field Alias");
            result.Severity.Should().Be(expectedSeverity);
            result.Category.Should().Be(Category.ResourceFields);
            result.LineNumber.Should().Be(14);
            result.LinePosition.Should().Be(99);
            result.Path.Should().Be("properties.policyRule.if.allOf[1].field");
            result.Description.Should().Be(ReadOnlyFieldAliasTests.FindingDescription);
        }

        /// <summary>
        /// Creates an effect parameter.
        /// </summary>
        /// <param name="type">The parameter type.</param>
        /// <param name="defaultValue">The default value.</param>
        /// <param name="allowedValues">The allowed values JSON.</param>
        /// <returns>The parameter JSON.</returns>
        private static string CreateEffectParameter(string type, string defaultValue, string allowedValues)
        {
            var defaultValueProperty = defaultValue == null
                ? string.Empty
                : $@", ""defaultValue"": ""{defaultValue}""";
            var allowedValuesProperty = allowedValues == null
                ? string.Empty
                : $@", ""allowedValues"": {allowedValues}";

            return $@"""effect"": {{ ""type"": ""{type}""{defaultValueProperty}{allowedValuesProperty} }}";
        }

        /// <summary>
        /// Creates a policy definition.
        /// </summary>
        /// <param name="parameters">The parameter definitions.</param>
        /// <param name="effect">The effect JSON.</param>
        /// <returns>The policy definition.</returns>
        private static string CreatePolicy(string parameters, string effect)
        {
            var parametersProperty = parameters == null
                ? string.Empty
                : $@"""parameters"": {{ {parameters} }},";

            return $@"
                {{
                  ""properties"": {{
                    ""mode"": ""Indexed"",
                    {parametersProperty}
                    ""policyRule"": {{
                      ""if"": {{
                        ""allOf"": [
                          {{
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          }},
                          {{
                            ""field"": ""Microsoft.Storage/storageAccounts/privateEndpointConnections"",
                            ""equals"": ""Something""
                          }}
                        ]
                      }},
                      ""then"": {{
                        ""effect"": {effect}
                      }}
                    }}
                  }}
                }}";
        }
    }
}
