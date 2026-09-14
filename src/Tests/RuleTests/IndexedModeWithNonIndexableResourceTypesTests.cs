namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Newtonsoft.Json.Linq;
    using Xunit;

    public class IndexedModeWithNonIndexableResourceTypesTests
    {
        private static readonly MockTypeMetadata Metadata = new()
        {
            Capabilities =
            {
                ["Contoso.Test/tracked"] = ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation,
                ["Contoso.Test/tagsOnly"] = ResourceTypeCapabilities.SupportsTags,
                ["Contoso.Test/locationOnly"] = ResourceTypeCapabilities.SupportsLocation,
                ["Contoso.Test/untracked"] = ResourceTypeCapabilities.None,
                ["Microsoft.Resources/resourceGroups"] = ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation,
                ["Microsoft.Resources/subscriptions/resourceGroups"] = ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation,
                ["Microsoft.Resources/subscriptions"] = ResourceTypeCapabilities.SupportsTags | ResourceTypeCapabilities.SupportsLocation,
            }
        };

        [Theory]
        [InlineData("Contoso.Test/untracked")]
        [InlineData("Contoso.Test/tagsOnly")]
        [InlineData("Contoso.Test/locationOnly")]
        [InlineData("CONTOSO.TEST/UNTRACKED")]
        [InlineData("Microsoft.Resources/resourceGroups")]
        [InlineData("Microsoft.Resources/subscriptions/resourceGroups")]
        [InlineData("Microsoft.Resources/subscriptions")]
        public void RuleTests_IndexedModeWithNonIndexableResourceTypes_RequiresAll(string resourceType)
        {
            var results = IndexedModeWithNonIndexableResourceTypesTests.Lint(
                mode: "'Indexed'", condition: $"{{ 'field': 'type', 'equals': '{resourceType}' }}");

            IndexedModeWithNonIndexableResourceTypesTests.AssertError(
                results: results, resourceType: resourceType, lineNumber: 3, linePosition: 21, path: "properties.mode");
        }

        [Theory]
        [InlineData("'iNdExEd'", 3, 21, "properties.mode")]
        [InlineData(null, 2, 17, "properties")]
        [InlineData("null", 2, 17, "properties")]
        public void RuleTests_IndexedModeWithNonIndexableResourceTypes_IndexedAndDefaultModes(
            string mode, int lineNumber, int linePosition, string path)
        {
            var results = IndexedModeWithNonIndexableResourceTypesTests.Lint(
                mode: mode, condition: "{ 'field': 'type', 'equals': 'Contoso.Test/untracked' }");

            IndexedModeWithNonIndexableResourceTypesTests.AssertError(
                results: results, resourceType: "Contoso.Test/untracked", lineNumber: lineNumber, linePosition: linePosition, path: path);
        }

        [Theory]
        [InlineData("'All'")]
        [InlineData("'Microsoft.Kubernetes.Data'")]
        [InlineData("'UnknownMode'")]
        [InlineData("\"[parameters('mode')]\"")]
        public void RuleTests_IndexedModeWithNonIndexableResourceTypes_OtherModes(string mode)
        {
            IndexedModeWithNonIndexableResourceTypesTests.Lint(
                mode: mode, condition: "{ 'field': 'type', 'equals': 'Contoso.Test/untracked' }").Should().BeEmpty();
        }

        [Theory]
        [InlineData("{ 'field': 'type', 'equals': 'Contoso.Test/tracked' }")]
        [InlineData("{ 'field': 'type', 'equals': 'Unknown.Provider/widgets' }")]
        [InlineData("{ 'field': 'type', 'in': [] }")]
        [InlineData("{ 'field': 'location', 'equals': 'westus' }")]
        public void RuleTests_IndexedModeWithNonIndexableResourceTypes_NoKnownMismatch(string condition)
        {
            IndexedModeWithNonIndexableResourceTypesTests.Lint(mode: "'Indexed'", condition: condition).Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_IndexedModeWithNonIndexableResourceTypes_MixedTypesReportKnownMismatch()
        {
            var results = IndexedModeWithNonIndexableResourceTypesTests.Lint(
                mode: "'Indexed'",
                condition: "{ 'field': 'type', 'in': ['Unknown.Provider/widgets', 'Contoso.Test/tracked', 'Contoso.Test/untracked'] }");

            IndexedModeWithNonIndexableResourceTypesTests.AssertError(
                results: results, resourceType: "Contoso.Test/untracked", lineNumber: 3, linePosition: 21, path: "properties.mode");
        }

        [Fact]
        public void RuleTests_IndexedModeWithNonIndexableResourceTypes_SimpleParameter()
        {
            var results = IndexedModeWithNonIndexableResourceTypesTests.Lint(
                mode: "'Indexed'",
                condition: @"{ 'field': 'type', 'equals': ""[parameters('type')]"" }",
                parameters: "{ 'type': { 'type': 'String', 'defaultValue': 'Contoso.Test/untracked' } }");

            IndexedModeWithNonIndexableResourceTypesTests.AssertError(
                results: results, resourceType: "Contoso.Test/untracked", lineNumber: 3, linePosition: 21, path: "properties.mode");
        }

        private static void AssertError(LinterOutput[] results, string resourceType, int lineNumber, int linePosition, string path)
        {
            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "indexed-mode-with-non-indexable-resource-types",
                Title: "Indexed Mode With Non-Indexable Resource Types",
                Category: Category.ResourceFields,
                Severity: Severity.Error,
                LineNumber: lineNumber,
                LinePosition: linePosition,
                Description: $"The policy mode 'Indexed' does not evaluate the referenced resource type '{resourceType}'. Set the mode to 'All' to include this resource type in policy evaluation.",
                Path: path,
                DocumentationUrl: "https://github.com/Azure/azure-policy-linter/blob/main/docs/Rules/indexed-mode-with-non-indexable-resource-types.md"));
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
                rules: new ILinterRule[] { new IndexedModeWithNonIndexableResourceTypes() },
                metadata: IndexedModeWithNonIndexableResourceTypesTests.Metadata);
            return linter.Lint(rawPolicyDefinition: policy.ToString());
        }
    }
}
