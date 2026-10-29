namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="ResourceTypeNotEvaluatedByPolicy"/> rule.
    /// </summary>
    public class ResourceTypeNotEvaluatedByPolicyTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        private static string Policy(string condition, string mode = "All") => @"{
  ""properties"": {
    ""mode"": """ + mode + @""",
    ""policyRule"": {
      ""if"": " + condition + @",
      ""then"": { ""effect"": ""deny"" }
    }
  }
}";

        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new ResourceTypeNotEvaluatedByPolicy() },
                metadata: ResourceTypeNotEvaluatedByPolicyTests.TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        private static LinterOutput Output(string resourceTypes) => new LinterOutput(
            RuleIdentifier: "resource-type-not-evaluated-by-policy",
            Title: "Resource Type Not Evaluated by Policy",
            Severity: Severity.Error,
            Category: Category.ResourceFields,
            LineNumber: 5,
            LinePosition: 13,
            Path: "properties.policyRule.if",
            Description: $"The policy targets resource types that Azure Policy doesn't evaluate: '{resourceTypes}'. The policy has no effect on resources of these types.");

        [Theory]
        [InlineData("Microsoft.Resources/deployments")]
        [InlineData("microsoft.billing/billingAccounts")]
        [InlineData("Microsoft.Capacity/reservationOrders/reservations")]
        [InlineData("Microsoft.ServiceBus/namespaces/topics")]
        public void RuleTests_ResourceTypeNotEvaluatedByPolicy_TypeCondition(string resourceType)
        {
            var results = ResourceTypeNotEvaluatedByPolicyTests.Lint(ResourceTypeNotEvaluatedByPolicyTests.Policy(
                condition: @"{ ""field"": ""type"", ""equals"": """ + resourceType + @""" }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(ResourceTypeNotEvaluatedByPolicyTests.Output(resourceType));
        }

        [Fact]
        public void RuleTests_ResourceTypeNotEvaluatedByPolicy_FieldAlias()
        {
            var results = ResourceTypeNotEvaluatedByPolicyTests.Lint(ResourceTypeNotEvaluatedByPolicyTests.Policy(
                condition: @"{ ""field"": ""Microsoft.Resources/deployments/mode"", ""equals"": ""Complete"" }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(ResourceTypeNotEvaluatedByPolicyTests.Output("Microsoft.Resources/deployments"));
        }

        [Fact]
        public void RuleTests_ResourceTypeNotEvaluatedByPolicy_MultipleTypes()
        {
            var results = ResourceTypeNotEvaluatedByPolicyTests.Lint(ResourceTypeNotEvaluatedByPolicyTests.Policy(
                condition: @"{ ""field"": ""type"", ""in"": [ ""Microsoft.Storage/storageAccounts"", ""Microsoft.Resources/deployments"", ""Microsoft.Help/diagnostics"" ] }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(ResourceTypeNotEvaluatedByPolicyTests.Output("Microsoft.Help/diagnostics, Microsoft.Resources/deployments"));
        }

        [Theory]
        [InlineData("Microsoft.Resources/subscriptions")]
        [InlineData("Microsoft.Resources/subscriptions/resourceGroups")]
        [InlineData("Microsoft.Capacity/reservationOrders")]
        [InlineData("Microsoft.ServiceBus/namespaces/queues")]
        [InlineData("Microsoft.Storage/storageAccounts")]
        public void RuleTests_ResourceTypeNotEvaluatedByPolicy_EvaluatedType(string resourceType)
        {
            var results = ResourceTypeNotEvaluatedByPolicyTests.Lint(ResourceTypeNotEvaluatedByPolicyTests.Policy(
                condition: @"{ ""field"": ""type"", ""equals"": """ + resourceType + @""" }"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ResourceTypeNotEvaluatedByPolicy_ResourceProviderMode()
        {
            var results = ResourceTypeNotEvaluatedByPolicyTests.Lint(ResourceTypeNotEvaluatedByPolicyTests.Policy(
                condition: @"{ ""field"": ""type"", ""equals"": ""Microsoft.Resources/deployments"" }",
                mode: "Microsoft.Kubernetes.Data"));

            results.Should().BeEmpty();
        }
    }
}
