// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System.Collections.Immutable;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for <see cref="FieldAliasFindingGroup"/>.
    /// </summary>
    public class FieldAliasFindingGroupTests
    {
        /// <summary>
        /// Duplicate aliases reach grouping and are deduplicated and sorted there.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasFindingGroup_Create_DeduplicatesAndSortsAliases()
        {
            var apiVersionSubset = ApiVersionSubset.CreateOptional(
                propertyMetadata: new[]
                {
                    new ResourcePropertyMetadata
                    {
                        ResourceType = "Microsoft.Test/widgets",
                        ApiVersions = ImmutableArray.Create("2025-01-01"),
                        Exists = true,
                        IsRequired = false,
                    },
                });

            var aliasDetails = new[]
            {
                (Alias: "Microsoft.Test/widgets/zeta", ApiVersionSubset: apiVersionSubset),
                (Alias: "Microsoft.Test/widgets/Alpha", ApiVersionSubset: apiVersionSubset),
                (Alias: "microsoft.test/widgets/alpha", ApiVersionSubset: apiVersionSubset),
                (Alias: "Microsoft.Test/widgets/beta", ApiVersionSubset: apiVersionSubset),
            };

            aliasDetails.Should().HaveCount(4);

            var groups = FieldAliasFindingGroup.Create(aliasDetails: aliasDetails);

            groups.Should().ContainSingle();
            groups[0].Aliases.Should().Equal(
                "Microsoft.Test/widgets/Alpha",
                "Microsoft.Test/widgets/beta",
                "Microsoft.Test/widgets/zeta");
        }

        /// <summary>
        /// Distinct API-version subsets remain separate when their summaries match.
        /// </summary>
        [Fact]
        public void RuleTests_FieldAliasFindingGroup_Create_DistinctSubsetsWithIdenticalSummaries_KeepsSeparateGroups()
        {
            var allowBlobPublicAccessApiVersions = ApiVersionSubset.CreateOptional(
                propertyMetadata: new[]
                {
                    new ResourcePropertyMetadata
                    {
                        ResourceType = "Microsoft.Storage/storageAccounts",
                        ApiVersions = ImmutableArray.Create("2021-04-01", "2022-09-01", "2023-05-01"),
                        Exists = true,
                        IsRequired = false,
                    },
                });
            var minimumTlsVersionApiVersions = ApiVersionSubset.CreateOptional(
                propertyMetadata: new[]
                {
                    new ResourcePropertyMetadata
                    {
                        ResourceType = "Microsoft.Storage/storageAccounts",
                        ApiVersions = ImmutableArray.Create("2021-09-01", "2022-09-01", "2023-05-01"),
                        Exists = true,
                        IsRequired = false,
                    },
                });

            allowBlobPublicAccessApiVersions.Should().NotBe(minimumTlsVersionApiVersions);
            allowBlobPublicAccessApiVersions!
                .Format()
                .Should()
                .Be("2023-05-01, 2022-09-01, and 1 older API version");
            minimumTlsVersionApiVersions!
                .Format()
                .Should()
                .Be(allowBlobPublicAccessApiVersions.Format());

            var groups = FieldAliasFindingGroup.Create(
                aliasDetails: new[]
                {
                    (Alias: "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", ApiVersionSubset: allowBlobPublicAccessApiVersions),
                    (Alias: "Microsoft.Storage/storageAccounts/minimumTlsVersion", ApiVersionSubset: minimumTlsVersionApiVersions),
                });

            groups.Should().HaveCount(2);
            groups[0].Aliases.Should().Equal("Microsoft.Storage/storageAccounts/allowBlobPublicAccess");
            groups[1].Aliases.Should().Equal("Microsoft.Storage/storageAccounts/minimumTlsVersion");
        }
    }
}
