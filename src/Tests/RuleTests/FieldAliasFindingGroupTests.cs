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
    }
}
