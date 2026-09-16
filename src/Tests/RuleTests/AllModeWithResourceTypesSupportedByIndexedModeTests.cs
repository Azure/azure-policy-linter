namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Newtonsoft.Json.Linq;
    using Xunit;

    public class AllModeWithResourceTypesSupportedByIndexedModeTests
    {
        private static readonly MockTypeMetadata Metadata = new()
        {
            Capabilities =
            {
                ["Contoso.Test/first"] = ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation,
                ["Contoso.Test/second"] = ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation,
                ["Contoso.Test/tagsOnly"] = ResourceTypeCapabilities.SupportsTags,
                ["Contoso.Test/locationOnly"] = ResourceTypeCapabilities.SupportsLocation,
                ["Contoso.Test/untracked"] = ResourceTypeCapabilities.None,
                ["Microsoft.Resources/resourceGroups"] = ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation,
                ["Microsoft.Resources/subscriptions/resourceGroups"] = ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation,
                ["Microsoft.Resources/subscriptions"] = ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation,
            }
        };

        [Theory]
        [InlineData("'All'", "{ 'field': 'type', 'equals': 'Contoso.Test/first' }")]
        [InlineData("'aLl'", "{ 'field': 'type', 'equals': 'CONTOSO.TEST/FIRST' }")]
        [InlineData("'All'", "{ 'field': 'type', 'in': ['Contoso.Test/first', 'Contoso.Test/second'] }")]
        public void RuleTests_AllModeWithResourceTypesSupportedByIndexedMode_AllTypesSupportIndexed(string mode, string condition)
        {
            var results = AllModeWithResourceTypesSupportedByIndexedModeTests.Lint(mode: mode, condition: condition);

            AllModeWithResourceTypesSupportedByIndexedModeTests.AssertInformational(results: results);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("null")]
        [InlineData("'Indexed'")]
        [InlineData("'Microsoft.Kubernetes.Data'")]
        [InlineData("\"[parameters('mode')]\"")]
        public void RuleTests_AllModeWithResourceTypesSupportedByIndexedMode_OtherModes(string mode)
        {
            AllModeWithResourceTypesSupportedByIndexedModeTests.Lint(
                mode: mode, condition: "{ 'field': 'type', 'equals': 'Contoso.Test/first' }").Should().BeEmpty();
        }

        [Theory]
        [InlineData("{ 'field': 'type', 'in': [] }")]
        [InlineData("{ 'field': 'location', 'equals': 'westus' }")]
        [InlineData("{ 'field': 'type', 'equals': 'Unknown.Provider/widgets' }")]
        [InlineData("{ 'field': 'type', 'in': ['Contoso.Test/first', 'Unknown.Provider/widgets'] }")]
        [InlineData("{ 'field': 'type', 'in': ['Contoso.Test/first', 'Contoso.Test/untracked'] }")]
        [InlineData("{ 'field': 'type', 'equals': 'Contoso.Test/tagsOnly' }")]
        [InlineData("{ 'field': 'type', 'equals': 'Contoso.Test/locationOnly' }")]
        [InlineData("{ 'field': 'type', 'equals': 'Microsoft.Resources/resourceGroups' }")]
        [InlineData("{ 'field': 'type', 'equals': 'Microsoft.Resources/subscriptions/resourceGroups' }")]
        [InlineData("{ 'field': 'type', 'equals': 'Microsoft.Resources/subscriptions' }")]
        public void RuleTests_AllModeWithResourceTypesSupportedByIndexedMode_NotAllTypesSupportIndexed(string condition)
        {
            AllModeWithResourceTypesSupportedByIndexedModeTests.Lint(mode: "'All'", condition: condition).Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_AllModeWithResourceTypesSupportedByIndexedMode_SimpleParameter()
        {
            var results = AllModeWithResourceTypesSupportedByIndexedModeTests.Lint(
                mode: "'All'",
                condition: @"{ 'field': 'type', 'in': ""[parameters('types')]"" }",
                parameters: "{ 'types': { 'type': 'Array', 'defaultValue': ['Contoso.Test/first', 'Contoso.Test/second'] } }");

            AllModeWithResourceTypesSupportedByIndexedModeTests.AssertInformational(results: results);
        }

        private static void AssertInformational(LinterOutput[] results)
        {
            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "all-mode-with-resource-types-supported-by-indexed-mode",
                Title: "All Mode With Resource Types Supported by Indexed Mode",
                Category: Category.BestPractices,
                Severity: Severity.Informational,
                LineNumber: 3,
                LinePosition: 17,
                Description: "The policy mode is 'All', and every referenced resource type supports tags and location. Consider 'Indexed' mode to restrict evaluation to resource types with those capabilities.",
                Path: "properties.mode",
                DocumentationUrl: "https://github.com/Azure/azure-policy-linter/blob/main/docs/Rules/all-mode-with-resource-types-supported-by-indexed-mode.md"));
        }

        private static LinterOutput[] Lint(string mode, string condition, string parameters = null)
        {
            var properties = new JObject();
            if (mode != null)
            {
                properties["mode"] = JToken.Parse(json: mode);
            }
            properties["policyRule"] = new JObject
            {
                ["if"] = JObject.Parse(json: condition),
                ["then"] = new JObject { ["effect"] = "audit" }
            };
            if (parameters != null)
            {
                properties["parameters"] = JObject.Parse(json: parameters);
            }
            var policy = new JObject { ["properties"] = properties };
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new AllModeWithResourceTypesSupportedByIndexedMode() },
                metadata: AllModeWithResourceTypesSupportedByIndexedModeTests.Metadata);
            return linter.Lint(rawPolicyDefinition: policy.ToString());
        }
    }
}
