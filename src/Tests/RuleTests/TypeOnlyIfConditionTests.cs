namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="TypeOnlyIfCondition"/> rule.
    /// </summary>
    public class TypeOnlyIfConditionTests
    {
        private const string TypeCondition = @"{ ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" }";

        private static readonly LinterOutput ExpectedOutput = new LinterOutput(
            RuleIdentifier: "type-only-if-condition",
            Title: "Type-Only If Condition",
            Severity: Severity.Informational,
            Category: Category.BestPractices,
            LineNumber: 5,
            LinePosition: 13,
            Path: "properties.policyRule.if",
            Description: "The policy's 'if' condition checks only the resource 'type'. Resources of the matching types are reported as non-compliant and all other resources as not applicable, so the policy never reports a resource as compliant.");

        private static string Policy(string condition, string effect = "audit", string parameters = "{}", string mode = "All") => @"{
  ""properties"": {
    ""mode"": """ + mode + @""",
    ""policyRule"": {
      ""if"": " + condition + @",
      ""then"": { ""effect"": """ + effect + @""" }
    },
    ""parameters"": " + parameters + @"
  }
}";

        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new TypeOnlyIfCondition() },
                metadata: new MockTypeMetadata());

            return linter.Lint(policyDefinition);
        }

        [Theory]
        [InlineData("audit")]
        [InlineData("Deny")]
        [InlineData("modify")]
        [InlineData("append")]
        public void RuleTests_TypeOnlyIfCondition_SingleTypeCondition(string effect)
        {
            var results = TypeOnlyIfConditionTests.Lint(TypeOnlyIfConditionTests.Policy(condition: TypeOnlyIfConditionTests.TypeCondition, effect: effect));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(TypeOnlyIfConditionTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_TypeOnlyIfCondition_MultipleTypeConditions()
        {
            var condition = @"{ ""anyOf"": [ { ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" }, { ""field"": ""Type"", ""in"": [ ""Microsoft.Compute/disks"" ] } ] }";

            var results = TypeOnlyIfConditionTests.Lint(TypeOnlyIfConditionTests.Policy(condition: condition));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(TypeOnlyIfConditionTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_TypeOnlyIfCondition_ParameterAllowsTypeApplicabilityEffects()
        {
            var results = TypeOnlyIfConditionTests.Lint(TypeOnlyIfConditionTests.Policy(
                condition: TypeOnlyIfConditionTests.TypeCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [ ""Audit"", ""Deny"", ""Disabled"" ] } }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(TypeOnlyIfConditionTests.ExpectedOutput);
        }

        [Theory]
        [InlineData(@"[ ""Audit"", ""AuditIfNotExists"" ]")]
        [InlineData(@"[ ""Disabled"" ]")]
        public void RuleTests_TypeOnlyIfCondition_ParameterAllowsOtherEffects(string allowedValues)
        {
            var results = TypeOnlyIfConditionTests.Lint(TypeOnlyIfConditionTests.Policy(
                condition: TypeOnlyIfConditionTests.TypeCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": " + allowedValues + @" } }"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_TypeOnlyIfCondition_ParameterWithoutAllowedValues()
        {
            var results = TypeOnlyIfConditionTests.Lint(TypeOnlyIfConditionTests.Policy(
                condition: TypeOnlyIfConditionTests.TypeCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""defaultValue"": ""Audit"" } }"));

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("auditIfNotExists")]
        [InlineData("disabled")]
        public void RuleTests_TypeOnlyIfCondition_OtherEffect(string effect)
        {
            var results = TypeOnlyIfConditionTests.Lint(TypeOnlyIfConditionTests.Policy(condition: TypeOnlyIfConditionTests.TypeCondition, effect: effect));

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData(@"{ ""field"": ""location"", ""equals"": ""westus"" }")]
        [InlineData(@"{ ""value"": ""[field('name')]"", ""equals"": ""a"" }")]
        [InlineData(@"{ ""count"": { ""field"": ""Microsoft.Test/resources/array[*]"" }, ""greater"": 0 }")]
        [InlineData(@"{ ""field"": ""type"", ""equals"": ""[field('tags.expectedType')]"" }")]
        public void RuleTests_TypeOnlyIfCondition_OtherCondition(string otherCondition)
        {
            var condition = @"{ ""allOf"": [ " + TypeOnlyIfConditionTests.TypeCondition + ", " + otherCondition + " ] }";

            var results = TypeOnlyIfConditionTests.Lint(TypeOnlyIfConditionTests.Policy(condition: condition));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_TypeOnlyIfCondition_ResourceProviderMode()
        {
            var results = TypeOnlyIfConditionTests.Lint(TypeOnlyIfConditionTests.Policy(condition: TypeOnlyIfConditionTests.TypeCondition, mode: "Microsoft.Kubernetes.Data"));

            results.Should().BeEmpty();
        }
    }
}
