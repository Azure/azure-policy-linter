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
                expectedEnforcementEffect: "deny",
                expectedCounterpart: "audit");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_ModifyRequiresAudit()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""modify""]",
                expectedEnforcementEffect: "modify",
                expectedCounterpart: "audit");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_AppendRequiresAudit()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""append""]",
                expectedEnforcementEffect: "append",
                expectedCounterpart: "audit");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_DeployIfNotExistsRequiresAuditIfNotExists()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""deployIfNotExists""]",
                expectedEnforcementEffect: "deployIfNotExists",
                expectedCounterpart: "auditIfNotExists");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_MultipleEffectsRequireAuditOnce()
        {
            MissingAuditEffectCounterpartTests.AssertFinding(
                allowedValues: @"[""deny"", ""modify"", ""append""]",
                expectedEnforcementEffect: "deny",
                expectedCounterpart: "audit");
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_EachMissingCounterpartIsReportedSeparately()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: @"[""deployIfNotExists"", ""deny""]");

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().HaveCount(2);
            results.Should().ContainEquivalentOf(MissingAuditEffectCounterpartTests.ExpectedOutput(
                enforcementEffect: "deny",
                counterpart: "audit"));
            results.Should().ContainEquivalentOf(MissingAuditEffectCounterpartTests.ExpectedOutput(
                enforcementEffect: "deployIfNotExists",
                counterpart: "auditIfNotExists"));
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_EffectValuesAreCaseInsensitive()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: @"[""DeNy"", ""DePlOyIfNoTeXiStS""]");

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().HaveCount(2);
            results.Should().ContainEquivalentOf(MissingAuditEffectCounterpartTests.ExpectedOutput(
                enforcementEffect: "deny",
                counterpart: "audit"));
            results.Should().ContainEquivalentOf(MissingAuditEffectCounterpartTests.ExpectedOutput(
                enforcementEffect: "deployIfNotExists",
                counterpart: "auditIfNotExists"));
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_AllCounterpartsPresent()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: @"[""deny"", ""modify"", ""append"", ""deployIfNotExists"", ""AUDIT"", ""AuditIfNotExists""]");

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_MissingAuditEffectCounterpart_DenyActionDoesNotRequireCounterpart()
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: @"[""denyAction""]");

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

        private static void AssertFinding(
            string allowedValues,
            string expectedEnforcementEffect,
            string expectedCounterpart)
        {
            var policyDefinition = MissingAuditEffectCounterpartTests.ParameterizedEffectPolicy(
                allowedValues: allowedValues);

            var results = MissingAuditEffectCounterpartTests
                .CreateLinter()
                .Lint(rawPolicyDefinition: policyDefinition);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(MissingAuditEffectCounterpartTests.ExpectedOutput(
                enforcementEffect: expectedEnforcementEffect,
                counterpart: expectedCounterpart));
        }

        private static LinterOutput ExpectedOutput(string enforcementEffect, string counterpart)
        {
            return new LinterOutput(
                RuleIdentifier: "missing-audit-effect-counterpart",
                Title: "Missing Audit Effect Counterpart",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: 33,
                Path: "properties.parameters.effect",
                Description: $"The effect parameter 'effect' allows the enforcement effect '{enforcementEffect}' but not its audit counterpart '{counterpart}'. Adding '{counterpart}' lets assignments use non-enforcing behavior without changing the policy definition.");
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
