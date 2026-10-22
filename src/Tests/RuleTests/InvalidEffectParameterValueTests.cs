namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="InvalidEffectParameterValue"/> rule.
    /// </summary>
    public class InvalidEffectParameterValueTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        /// <summary>
        /// Builds a policy definition whose effect is the 'effect' parameter. Parameters and mode follow the
        /// policy rule so the effect location is the same in every test.
        /// </summary>
        private static string Policy(string effectParameter, string modeProperty = @"""mode"": ""All"",") => @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": { ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" },
      ""then"": { ""effect"": ""[parameters('effect')]"" }
    },
    " + modeProperty + @"
    ""parameters"": { ""effect"": " + effectParameter + @" }
  }
}";

        private static LinterOutput ExpectedOutput(string value) => new LinterOutput(
            RuleIdentifier: "invalid-effect-parameter-value",
            Title: "Invalid Effect Parameter Value",
            Severity: Severity.Error,
            Category: Category.BestPractices,
            LineNumber: 5,
            LinePosition: 50,
            Path: "properties.policyRule.then.effect",
            Description: $"The effect parameter 'effect' allows the value '{value}', which is not a policy effect. Correct the value to the intended effect or remove it.");

        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new InvalidEffectParameterValue() },
                metadata: InvalidEffectParameterValueTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_UnknownAllowedValue()
        {
            var results = InvalidEffectParameterValueTests.Lint(InvalidEffectParameterValueTests.Policy(
                effectParameter: @"{ ""type"": ""String"", ""allowedValues"": [ ""Audit"", ""Deny"", ""Enabled"" ], ""defaultValue"": ""Audit"" }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(InvalidEffectParameterValueTests.ExpectedOutput(value: "Enabled"));
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_MultipleUnknownAllowedValues()
        {
            var results = InvalidEffectParameterValueTests.Lint(InvalidEffectParameterValueTests.Policy(
                effectParameter: @"{ ""type"": ""String"", ""allowedValues"": [ ""Audit"", ""Enabled"", ""EnforceRegoPolicy"", ""ENABLED"" ] }"));

            results.Should().HaveCount(2);
            results.Should().ContainEquivalentOf(InvalidEffectParameterValueTests.ExpectedOutput(value: "Enabled"));
            results.Should().ContainEquivalentOf(InvalidEffectParameterValueTests.ExpectedOutput(value: "EnforceRegoPolicy"));
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_SchemaEffectsAreUnknown()
        {
            var results = InvalidEffectParameterValueTests.Lint(InvalidEffectParameterValueTests.Policy(
                effectParameter: @"{ ""type"": ""String"", ""allowedValues"": [ ""AuditSchema"" ] }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(InvalidEffectParameterValueTests.ExpectedOutput(value: "AuditSchema"));
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_UnknownDefaultValueWithoutAllowedValues()
        {
            var results = InvalidEffectParameterValueTests.Lint(InvalidEffectParameterValueTests.Policy(
                effectParameter: @"{ ""type"": ""String"", ""defaultValue"": ""Enabled"" }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(InvalidEffectParameterValueTests.ExpectedOutput(value: "Enabled"));
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_UnknownDefaultValueWithEmptyAllowedValues()
        {
            var results = InvalidEffectParameterValueTests.Lint(InvalidEffectParameterValueTests.Policy(
                effectParameter: @"{ ""type"": ""String"", ""allowedValues"": [], ""defaultValue"": ""Enabled"" }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(InvalidEffectParameterValueTests.ExpectedOutput(value: "Enabled"));
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_IndexedMode()
        {
            var results = InvalidEffectParameterValueTests.Lint(InvalidEffectParameterValueTests.Policy(
                effectParameter: @"{ ""type"": ""String"", ""allowedValues"": [ ""Enabled"" ] }",
                modeProperty: @"""mode"": ""indexed"","));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(InvalidEffectParameterValueTests.ExpectedOutput(value: "Enabled"));
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_NoMode()
        {
            var results = InvalidEffectParameterValueTests.Lint(InvalidEffectParameterValueTests.Policy(
                effectParameter: @"{ ""type"": ""String"", ""allowedValues"": [ ""Enabled"" ] }",
                modeProperty: string.Empty));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(InvalidEffectParameterValueTests.ExpectedOutput(value: "Enabled"));
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_AllKnownEffects()
        {
            var results = InvalidEffectParameterValueTests.Lint(InvalidEffectParameterValueTests.Policy(
                effectParameter: @"{ ""type"": ""String"", ""allowedValues"": [ ""append"", ""AUDIT"", ""AuditAction"", ""auditIfNotExists"", ""Deny"", ""DenyAction"", ""DeployIfNotExists"", ""Disabled"", ""Manual"", ""Modify"" ], ""defaultValue"": ""Audit"" }"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_KnownDefaultValueWithoutAllowedValues()
        {
            var results = InvalidEffectParameterValueTests.Lint(InvalidEffectParameterValueTests.Policy(
                effectParameter: @"{ ""type"": ""String"", ""defaultValue"": ""audit"" }"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_ResourceProviderMode()
        {
            var results = InvalidEffectParameterValueTests.Lint(InvalidEffectParameterValueTests.Policy(
                effectParameter: @"{ ""type"": ""String"", ""allowedValues"": [ ""Audit"", ""Mutate"" ] }",
                modeProperty: @"""mode"": ""Microsoft.Kubernetes.Data"","));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_InvalidEffectParameterValue_LiteralEffect()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": { ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" },
      ""then"": { ""effect"": ""Enabled"" }
    }
  }
}";

            InvalidEffectParameterValueTests.Lint(policyDefinition).Should().BeEmpty();
        }
    }
}
