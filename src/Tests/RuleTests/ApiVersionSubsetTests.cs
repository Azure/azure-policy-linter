namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System.Collections.Immutable;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for <see cref="ApiVersionSubset"/>.
    /// </summary>
    public class ApiVersionSubsetTests
    {
        /// <summary>
        /// Equivalent optional API versions normalize to equal subsets.
        /// </summary>
        [Fact]
        public void RuleTests_ApiVersionSubset_CreateOptional_EquivalentVersions_AreEqual()
        {
            var first = ApiVersionSubset.CreateOptional(
                propertyMetadata: new[]
                {
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: new[] { "2025-01-01", "2024-01-01", "2025-01-01" },
                        exists: true),
                });
            var second = ApiVersionSubset.CreateOptional(
                propertyMetadata: new[]
                {
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: new[] { "2024-01-01", "2025-01-01" },
                        exists: true),
                });

            first.Should().Be(second);
            first.GetHashCode().Should().Be(second.GetHashCode());
            first.Format().Should().Be("2025-01-01, 2024-01-01");
        }

        /// <summary>
        /// Different optional API-version sets remain distinct when their summaries match.
        /// </summary>
        [Fact]
        public void RuleTests_ApiVersionSubset_CreateOptional_MatchingSummaries_RemainDistinct()
        {
            var first = ApiVersionSubset.CreateOptional(
                propertyMetadata: new[]
                {
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: new[] { "2023-01-01", "2024-01-01", "2025-01-01" },
                        exists: true),
                });
            var second = ApiVersionSubset.CreateOptional(
                propertyMetadata: new[]
                {
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: new[] { "2022-01-01", "2024-01-01", "2025-01-01" },
                        exists: true),
                });

            first.Format().Should().Be(second.Format());
            first.Should().NotBe(second);
            first.GetHashCode().Should().NotBe(second.GetHashCode());
        }

        /// <summary>
        /// Unavailable API versions and availability statistics determine the subset.
        /// </summary>
        [Fact]
        public void RuleTests_ApiVersionSubset_CreateUnavailable_DerivesVersionsStatisticsAndDetails()
        {
            var first = ApiVersionSubset.CreateUnavailableInOldApiVersions(
                propertyMetadata: new[]
                {
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: new[] { "2024-01-01", "2023-01-01", "2024-01-01" },
                        exists: false),
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: new[] { "2026-01-01", "2022-01-01", "2025-01-01" },
                        exists: true),
                });
            var equivalent = ApiVersionSubset.CreateUnavailableInOldApiVersions(
                propertyMetadata: new[]
                {
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: new[] { "2025-01-01", "2022-01-01", "2026-01-01" },
                        exists: true),
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: new[] { "2023-01-01", "2024-01-01" },
                        exists: false),
                });
            var differentStatistic = ApiVersionSubset.CreateUnavailableInOldApiVersions(
                propertyMetadata: new[]
                {
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: new[] { "2023-01-01", "2024-01-01" },
                        exists: false),
                    ResourcePropertyMetadataTestFactory.Create(
                        apiVersions: new[] { "2022-01-01", "2025-01-01" },
                        exists: true),
                });

            first.Format()
                .Should()
                .Be("unavailable in 2024-01-01, 2023-01-01 (available in 2 newer API versions)");
            first.Should().Be(equivalent);
            first.GetHashCode().Should().Be(equivalent.GetHashCode());
            first.Should().NotBe(differentStatistic);
            first.GetHashCode().Should().NotBe(differentStatistic.GetHashCode());
            differentStatistic.Format()
                .Should()
                .Be("unavailable in 2024-01-01, 2023-01-01 (available in 1 newer API version)");
        }
    }

    /// <summary>
    /// Creates resource property metadata for tests.
    /// </summary>
    internal static class ResourcePropertyMetadataTestFactory
    {
        /// <summary>
        /// Creates resource property metadata.
        /// </summary>
        /// <param name="apiVersions">The API versions.</param>
        /// <param name="exists">Whether the property exists.</param>
        /// <returns>The property metadata.</returns>
        internal static ResourcePropertyMetadata Create(
            string[] apiVersions,
            bool exists)
        {
            return new ResourcePropertyMetadata
            {
                ResourceType = "Microsoft.Test/widgets",
                ApiVersions = ImmutableArray.Create(apiVersions),
                Exists = exists,
                IsRequired = false,
            };
        }
    }
}
