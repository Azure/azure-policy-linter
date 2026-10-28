namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System.Collections.Immutable;
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions"/> rule.
    /// </summary>
    public class OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        /// <summary>
        /// Returns fixed metadata entries for any alias.
        /// </summary>
        private sealed class FixedMetadata : ITypeMetadata
        {
            private readonly ResourcePropertyMetadata[] entries;

            /// <summary>
            /// Initializes a new instance of the <see cref="FixedMetadata"/> class.
            /// </summary>
            /// <param name="entries">The metadata entries.</param>
            public FixedMetadata(params ResourcePropertyMetadata[] entries)
            {
                this.entries = entries;
            }

            /// <inheritdoc/>
            public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
            {
                result = this.entries;
                return true;
            }
        }

        private static ResourcePropertyMetadata Entry(string type, bool exists, params string[] apiVersions) => new ResourcePropertyMetadata
        {
            ResourceType = "Microsoft.Test/resources",
            ApiVersions = ImmutableArray.Create(apiVersions),
            Exists = exists,
            Type = type,
        };

        private static string Policy(string field, string operatorName, string value) => @"{
  ""properties"": {
    ""mode"": ""Indexed"",
    ""parameters"": { ""size"": { ""type"": ""Integer"" } },
    ""policyRule"": {
      ""if"": { ""field"": """ + field + @""", """ + operatorName + @""": " + value + @" },
      ""then"": { ""effect"": ""deny"" }
    }
  }
}";

        private static LinterOutput[] Lint(string policyDefinition, ITypeMetadata metadata)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions() },
                metadata: metadata);

            return linter.Lint(policyDefinition);
        }

        private static LinterOutput Output(int linePosition, string description) => new LinterOutput(
            RuleIdentifier: "ordering-operator-on-incompatible-field-type-in-old-api-versions",
            Title: "Ordering Operator on Incompatible Field Type in Old API Versions",
            Severity: Severity.Warning,
            Category: Category.ResourceFields,
            LineNumber: 6,
            LinePosition: linePosition,
            Path: "properties.policyRule.if.greater",
            Description: description);

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions_StringInOldApiVersion()
        {
            var results = OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Lint(
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Policy("Microsoft.Sql/servers/databases/maxSizeBytes", "greater", "5"),
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.TypeMetadata);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Output(
                linePosition: 83,
                description: "The field alias 'Microsoft.Sql/servers/databases/maxSizeBytes' is of type 'string' in API versions '2014-04-01' and cannot be ordered with the 'greater' operator against a value of type 'number'. Requests that use these API versions fail evaluation, which implicitly denies the resource."));
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions_EntriesWithSameTypeCombined()
        {
            var metadata = new FixedMetadata(
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Entry("Number", true, "2024-01-01"),
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Entry("String", true, "2020-01-01"),
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Entry("String", true, "2019-01-01", "2018-01-01"));

            var results = OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Lint(
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Policy("Microsoft.Test/resources/size", "greater", "5"),
                metadata);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Output(
                linePosition: 68,
                description: "The field alias 'Microsoft.Test/resources/size' is of type 'string' in API versions '2018-01-01, 2019-01-01, 2020-01-01' and cannot be ordered with the 'greater' operator against a value of type 'number'. Requests that use these API versions fail evaluation, which implicitly denies the resource."));
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions_DecimalNumberOnOldIntegerField()
        {
            var metadata = new FixedMetadata(
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Entry("Number", true, "2024-01-01"),
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Entry("Integer", true, "2020-01-01"));

            var results = OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Lint(
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Policy("Microsoft.Test/resources/size", "greater", "5.5"),
                metadata);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Output(
                linePosition: 70,
                description: "The field alias 'Microsoft.Test/resources/size' is of type 'integer' in API versions '2020-01-01' and cannot be ordered with the 'greater' operator against a value of type 'decimal number'. Requests that use these API versions fail evaluation, which implicitly denies the resource."));
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions_IncompatibleInLatestApiVersion()
        {
            var results = OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Lint(
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Policy("Microsoft.Sql/servers/databases/maxSizeBytes", "greater", "\"abc\""),
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.TypeMetadata);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("Integer", true)]
        [InlineData("String", false)]
        [InlineData("Any", true)]
        [InlineData("NotSpecified", true)]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions_OldApiVersionNotReported(string oldType, bool oldExists)
        {
            var metadata = new FixedMetadata(
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Entry("Integer", true, "2024-01-01"),
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Entry(oldType, oldExists, "2020-01-01"));

            var results = OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Lint(
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Policy("Microsoft.Test/resources/size", "greater", "5"),
                metadata);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions_ParameterizedValue()
        {
            var results = OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Lint(
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Policy("Microsoft.Sql/servers/databases/maxSizeBytes", "greater", "\"[parameters('size')]\""),
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.TypeMetadata);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldTypeInOldApiVersions_NonOrderingOperator()
        {
            var results = OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Lint(
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.Policy("Microsoft.Sql/servers/databases/maxSizeBytes", "equals", "5"),
                OrderingOperatorOnIncompatibleFieldTypeInOldApiVersionsTests.TypeMetadata);

            results.Should().BeEmpty();
        }
    }
}
