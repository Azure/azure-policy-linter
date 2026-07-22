// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="MissingAuditEffectCounterpart"/> rule.
    /// </summary>
    public class MissingAuditEffectCounterpartTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_DenyRequiresAudit()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""deny""]",
                expectedMissingCounterparts: "'audit'");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_ModifyRequiresAudit()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""modify""]",
                expectedMissingCounterparts: "'audit'");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_AppendRequiresAudit()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""append""]",
                expectedMissingCounterparts: "'audit'");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_DeployIfNotExistsRequiresAuditIfNotExists()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""deployIfNotExists""]",
                expectedMissingCounterparts: "'auditIfNotExists'");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_DenyActionRequiresAuditAction()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""denyAction""]",
                expectedMissingCounterparts: "'auditAction'");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_MultipleEffectsRequireAuditOnce()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""deny"", ""modify"", ""append""]",
                expectedMissingCounterparts: "'audit'");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_MultipleMappingsUseDeterministicOrder()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""denyAction"", ""deployIfNotExists"", ""deny""]",
                expectedMissingCounterparts: "'audit', 'auditIfNotExists', 'auditAction'");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_EffectValuesAreCaseInsensitive()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""DeNy"", ""DePlOyIfNoTeXiStS"", ""DeNyAcTiOn""]",
                expectedMissingCounterparts: "'audit', 'auditIfNotExists', 'auditAction'");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_AllCounterpartsPresent()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: @"[""deny"", ""modify"", ""append"", ""deployIfNotExists"", ""denyAction"", ""AUDIT"", ""AuditIfNotExists"", ""auditAction""]");

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_AuditActionCounterpartPresent()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: @"[""denyAction"", ""AuditAction""]");

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_HardCodedEffect()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: @"[""deny""]",
                effectExpression: "deny");

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_ComplexEffect()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: @"[""deny""]",
                effectExpression: "[concat(parameters('effect'), '')]");

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_MissingAllowedValues()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: null);

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_EmptyAllowedValues()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: "[]");

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_NonStringParameter()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: "[1]",
                parameterType: "Integer");

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().BeEmpty();
        }

        private static PolicyLinter CreateLinter()
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingAuditEffectCounterpart(),
                },
                metadata: MissingAuditEffectCounterpartTests.MockMetadata);
        }

        private static void AssertFinding(string allowedValues, string expectedMissingCounterparts)
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: allowedValues);

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "missing-audit-effect-counterpart",
                Title: "Missing Audit Effect Counterpart",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 17,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: $"The effect parameter 'effect' is missing these audit counterparts from its allowedValues: {expectedMissingCounterparts}. Adding them lets assignments use non-enforcing behavior without changing the policy definition.");

            results.Should().ContainEquivalentOf(output);
        }

        private static string ParameterizedEffectPolicy(
            string allowedValues,
            string parameterType = "String",
            string effectExpression = "[parameters('effect')]")
        {
            var allowedValuesProperty = allowedValues == null
                ? string.Empty
                : @",
                        ""allowedValues"": " + allowedValues;

            return @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": """ + parameterType + @"""" + allowedValuesProperty + @"
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": """ + effectExpression + @"""
                      }
                    }
                  }
                }";
        }
    }
}
