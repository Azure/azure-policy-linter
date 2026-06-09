// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Tests
{
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Contracts;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Metadata;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Xunit;

    public class MetadataTests
    {
        private readonly MockAliasResolver mockAliasResolver;
        private readonly MockMetadataProvider mockMetadataProvider;

        public MetadataTests()
        {
            this.mockAliasResolver = new MockAliasResolver(MockResourceMetadata.Aliases);
            this.mockMetadataProvider = new MockMetadataProvider(MockResourceMetadata.ResourceTypeMetadata);
        }

        [Fact]
        void PolicyLinter_TypeMetadata_ResolveAlias()
        {
            var typeMetadata = new TypeMetadata(this.mockMetadataProvider, this.mockAliasResolver);

            // Not an alias
            typeMetadata.TryGetAliasPropertyMetadata("name", out _).Should().BeFalse();

            // Alias that doens't have type info
            typeMetadata.TryGetAliasPropertyMetadata("Microsoft.Test/noType", out var _).Should().BeFalse();

            // Alias that doesn't exist
            typeMetadata.TryGetAliasPropertyMetadata("Microsoft.Test/tests/nope", out _).Should().BeFalse();

            // null alias
            typeMetadata.TryGetAliasPropertyMetadata(null, out _).Should().BeFalse();

            // prop1 is a valid alias that looks the same across all API versions. Should get one metadata in the result.
            typeMetadata.TryGetAliasPropertyMetadata("Microsoft.Test/tests/prop1", out var prop1Metadata).Should().BeTrue();
            prop1Metadata.Should().HaveCount(1);

            this.mockAliasResolver.TryResolveAlias("Microsoft.Test/tests/prop1", out var prop1Alias).Should().BeTrue();
            prop1Metadata.Should().ContainEquivalentOf(new ResourcePropertyMetadata
            {
                Alias = prop1Alias,
                ApiVersions = new[] { "2025-01-01", "2024-01-01", "2023-01-01" }.ToImmutableArray(),
                Exists = true,
                ResourceType = MockResourceMetadata.FullyQualifiedResourceType,
                Path = "properties.prop1",
                Type = "String",
                IsReadonly = true,
                IsRequired = true,
                IsImmutable = true,
                IsConditional = false,
            });

            // prop2 is a valid aliastargeting paths in 3 specific API versions in addition to the default path.
            // In 2024-01-01, it is conditional property that is also readonly, required and immutable.
            // In 2023-01-01, it is not available but we have metadata for this API version, meaning that the alias seems to be mapping to the wrong property. Expect unresolved metadata indicating that for this version the property is missing.
            // The alias also defines a path for 2022-01-01 for which we have no metadata, meaning that this alias path is not really being used and so we should expect no metadata for it.
            typeMetadata.TryGetAliasPropertyMetadata("Microsoft.Test/tests/prop2", out var prop2Metadata).Should().BeTrue();
            prop2Metadata.Should().HaveCount(3);

            this.mockAliasResolver.TryResolveAlias("Microsoft.Test/tests/prop2", out var prop2Alias).Should().BeTrue();
            prop2Metadata.Should().ContainEquivalentOf(new ResourcePropertyMetadata
            {
                Alias = prop2Alias,
                ApiVersions = new[] { "2025-01-01" }.ToImmutableArray(),
                Exists = true,
                ResourceType = MockResourceMetadata.FullyQualifiedResourceType,
                Path = "properties.prop2",
                Type = "String",
                IsReadonly = false,
                IsRequired = false,
                IsImmutable = false,
                IsConditional = false,
            });

            prop2Metadata.Should().ContainEquivalentOf(new ResourcePropertyMetadata
            {
                Alias = prop2Alias,
                ApiVersions = new[] { "2024-01-01" }.ToImmutableArray(),
                Exists = true,
                ResourceType = MockResourceMetadata.FullyQualifiedResourceType,
                Path = "properties.old.prop2",
                Type = "String",
                IsReadonly = true,
                IsRequired = true,
                IsImmutable = true,
                IsConditional = true,
            });

            prop2Metadata.Should().ContainEquivalentOf(new ResourcePropertyMetadata
            {
                Alias = prop2Alias,
                ApiVersions = new[] { "2023-01-01" }.ToImmutableArray(),
                Exists = false,
                ResourceType = MockResourceMetadata.FullyQualifiedResourceType,
                IsConditional = false,
                IsImmutable = false,
                IsReadonly = false,
                IsRequired = false,
                Path = "properties.old.prop2",
                Type = string.Empty,
            });
        }

        private static class MockResourceMetadata
        {
            public const string FullyQualifiedResourceType = "Microsoft.Test/tests";

            public static readonly string[] ApiVersions = new[] { "2025-01-01", "2024-01-01", "2023-01-01" };

            public static readonly ResourceTypeMetadata[] ResourceTypeMetadata = new[] {
                // In API version 2025-01-01, prop1 is read-only, required, and immutable.
                new ResourceTypeMetadata
                {
                    FullyQualifiedResourceType = FullyQualifiedResourceType,
                    ApiVersion = "2025-01-01",
                    AllPropertyPaths = new OrdinalInsensitiveDictionary<TokenType>
                    {
                        ["$[*].properties.prop1"] = TokenType.String,
                        ["$[*].properties.prop2"] = TokenType.String,
                    },
                    ReadOnlyPropertyPaths = new List<string> { "$[*].properties.prop1" },
                    RequiredProperties = new List<string> { "$[*].properties.prop1" },
                    ImmutablePropertyPaths = new List<string> { "$[*].properties.prop1" }
                },
                // In API version 2024-01-01, both properties are read-only, required, and immutable.
                // prop2 is conditional
                // prop2 has a different path than the equivalent property in the previous version.
                new ResourceTypeMetadata
                {
                    FullyQualifiedResourceType = FullyQualifiedResourceType,
                    ApiVersion = "2024-01-01",
                    AllPropertyPaths = new OrdinalInsensitiveDictionary<TokenType>
                    {
                        ["$[*].properties.prop1"] = TokenType.String,
                        ["[?(@.properties.kind=='awesome')].properties.old.prop2"] = TokenType.String,
                    },
                    ReadOnlyPropertyPaths = new List<string> { "$[*].properties.prop1", "[?(@.properties.kind=='awesome')].properties.old.prop2" },
                    RequiredProperties = new List<string> { "$[*].properties.prop1", "[?(@.properties.kind=='awesome')].properties.old.prop2" },
                    ImmutablePropertyPaths = new List<string> { "$[*].properties.prop1", "[?(@.properties.kind=='awesome')].properties.old.prop2" }
                },
                // In API version 2023-01-01, only prop1 exists.
                new ResourceTypeMetadata
                {
                    FullyQualifiedResourceType = FullyQualifiedResourceType,
                    ApiVersion = "2023-01-01",
                    AllPropertyPaths = new OrdinalInsensitiveDictionary<TokenType>
                    {
                        ["$[*].properties.prop1"] = TokenType.String
                    },
                    ReadOnlyPropertyPaths = new List<string> { "$[*].properties.prop1" },
                    RequiredProperties = new List<string> { "$[*].properties.prop1" },
                    ImmutablePropertyPaths = new List<string> { "$[*].properties.prop1" }
                },
            };

            public static readonly Dictionary<string, AliasDetails> Aliases = new()
            {
                ["Microsoft.Test/tests/prop1"] = new AliasDetails
                {
                    Name = "Microsoft.Test/tests/prop1",
                    DefaultPath = "properties.prop1"
                },
                ["Microsoft.Test/tests/prop2"] = new AliasDetails
                {
                    Name = "Microsoft.Test/tests/prop2",
                    DefaultPath = "properties.prop2",
                    Paths = new AliasPath[]
                    {
                        new AliasPath
                        {
                            ApiVersions = new[] { "2024-01-01" },
                            Path = "properties.old.prop2",
                        },
                        new AliasPath
                        {
                            ApiVersions = new[] { "2023-01-01" },
                            Path = "properties.old.prop2",
                        },
                        new AliasPath
                        {
                            ApiVersions = new[] { "2023-01-01" },
                            Path = "properties.old.prop2",
                        }
                    }
                },
                ["Microsoft.Test/noType"] = new AliasDetails
                {
                    Name = "Microsoft.Test/noType",
                    DefaultPath = "properties.noType"
                },

            };
        }

        private class MockAliasResolver : IAliasResolver
        {
            private readonly Dictionary<string, AliasDetails> aliases;

            public MockAliasResolver(Dictionary<string, AliasDetails> aliases)
            {
                this.aliases = aliases;
            }

            public bool TryResolveAlias(string alias, out AliasDetails resolvedAlias)
            {
                return this.aliases.TryGetValue(alias, out resolvedAlias);
            }
        }

        private class MockMetadataProvider : IResourceTypeMetadataProvider
        {
            private readonly ResourceTypeMetadata[] metadata;

            public MockMetadataProvider(ResourceTypeMetadata[] metadata)
            {
                this.metadata = metadata;
            }

            public IEnumerable<ResourceTypeMetadata> GetApiVersionMetadataForResourceType(string fullyQualifiedResourceType)
            {
                return this.metadata.Where(metadata => metadata.FullyQualifiedResourceType == fullyQualifiedResourceType);
            }

            public IEnumerable<string> GetAvailableFullyQualifiedResourceTypes()
            {
                return this.metadata.Select(metadata => metadata.FullyQualifiedResourceType).Distinct();
            }

            public ResourceTypeMetadata GetMetadata(string fullyQualifiedResourceType, string apiVersion)
            {
                return this.metadata.FirstOrDefault(metadata => metadata.FullyQualifiedResourceType == fullyQualifiedResourceType && metadata.ApiVersion == apiVersion);
            }
        }

    }
}
