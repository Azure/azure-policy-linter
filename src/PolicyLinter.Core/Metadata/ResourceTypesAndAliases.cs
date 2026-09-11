// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Metadata
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.IO;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json;

    /// <summary>
    /// Loads resource types and aliases from the public-cloud snapshot.
    /// </summary>
    internal static class ResourceTypesAndAliases
    {
        private const string ResourcePrefix = "ResourceTypesAndAliases.";
        private const string TypesSuffix = ".types.json";
        private const string AliasesSuffix = ".aliases.json";

        private static readonly Dictionary<string, Lazy<ImmutableDictionary<string, AliasDetails>>> aliases =
            new(comparer: StringComparer.OrdinalIgnoreCase);

        private static readonly Dictionary<string, Lazy<ImmutableDictionary<string, ResourceTypeCapabilities>>> capabilities =
            new(comparer: StringComparer.OrdinalIgnoreCase);

        static ResourceTypesAndAliases()
        {
            foreach (var name in typeof(ResourceTypesAndAliases).Assembly.GetManifestResourceNames())
            {
                if (!name.StartsWith(value: ResourceTypesAndAliases.ResourcePrefix, comparisonType: StringComparison.Ordinal))
                {
                    continue;
                }

                if (name.EndsWith(value: ResourceTypesAndAliases.AliasesSuffix, comparisonType: StringComparison.Ordinal))
                {
                    var providerNamespace = name[ResourceTypesAndAliases.ResourcePrefix.Length..^ResourceTypesAndAliases.AliasesSuffix.Length];
                    ResourceTypesAndAliases.aliases.Add(
                        key: providerNamespace,
                        value: new Lazy<ImmutableDictionary<string, AliasDetails>>(
                            valueFactory: () => ResourceTypesAndAliases.LoadAliases(resourceName: name)));
                }
                else if (name.EndsWith(value: ResourceTypesAndAliases.TypesSuffix, comparisonType: StringComparison.Ordinal))
                {
                    var providerNamespace = name[ResourceTypesAndAliases.ResourcePrefix.Length..^ResourceTypesAndAliases.TypesSuffix.Length];
                    ResourceTypesAndAliases.capabilities.Add(
                        key: providerNamespace,
                        value: new Lazy<ImmutableDictionary<string, ResourceTypeCapabilities>>(
                            valueFactory: () => ResourceTypesAndAliases.LoadCapabilities(resourceName: name)));
                }
            }
        }

        /// <summary>
        /// Resolves an alias without loading other namespaces or their capabilities.
        /// </summary>
        /// <param name="aliasName">The fully qualified alias name.</param>
        /// <param name="result">The resolved alias.</param>
        public static bool TryResolveAlias(string aliasName, out AliasDetails? result)
        {
            result = null;
            var separator = aliasName.IndexOf(value: '/');
            return separator > 0
                && ResourceTypesAndAliases.aliases.TryGetValue(key: aliasName[..separator], value: out var namespaceAliases)
                && namespaceAliases.Value.TryGetValue(key: aliasName, value: out result);
        }

        /// <summary>
        /// Gets resource type capabilities without loading aliases.
        /// </summary>
        /// <param name="resourceType">The fully qualified resource type.</param>
        /// <param name="result">The known capabilities.</param>
        public static bool TryGetCapabilities(string? resourceType, out ResourceTypeCapabilities? result)
        {
            result = null;
            if (resourceType == null)
            {
                return false;
            }

            var separator = resourceType.IndexOf(value: '/');
            return separator > 0
                && ResourceTypesAndAliases.capabilities.TryGetValue(key: resourceType[..separator], value: out var namespaceCapabilities)
                && namespaceCapabilities.Value.TryGetValue(key: resourceType[(separator + 1)..], value: out result);
        }

        private static ImmutableDictionary<string, AliasDetails> LoadAliases(string resourceName)
        {
            // For aliases shared by multiple resource types, the last entry wins.
            return ResourceTypesAndAliases.LoadProvider(resourceName: resourceName).ResourceTypes
                .SelectMany(selector: type => type.Aliases)
                .ToOrdinalInsensitiveDictionary(keySelector: alias => alias.Name, elementSelector: alias => alias)
                .ToImmutableDictionary(keyComparer: StringComparer.OrdinalIgnoreCase);
        }

        private static ImmutableDictionary<string, ResourceTypeCapabilities> LoadCapabilities(string resourceName)
        {
            var result = ImmutableDictionary.CreateBuilder<string, ResourceTypeCapabilities>(keyComparer: StringComparer.OrdinalIgnoreCase);
            foreach (var type in ResourceTypesAndAliases.LoadProvider(resourceName: resourceName).ResourceTypes)
            {
                var capabilities = type.Capabilities;
                if (!string.IsNullOrWhiteSpace(value: capabilities))
                {
                    result.Add(key: type.ResourceType, value: new ResourceTypeCapabilities(capabilities: capabilities));
                }
            }
            return result.ToImmutable();
        }

        private static ProviderTypesAndAliases LoadProvider(string resourceName)
        {
            using var stream = typeof(ResourceTypesAndAliases).Assembly.GetManifestResourceStream(name: resourceName)
                ?? throw new FileNotFoundException(message: $"Resource snapshot '{resourceName}' was not found.");
            using var streamReader = new StreamReader(stream: stream);
            using var reader = new JsonTextReader(reader: streamReader);
            return JsonExtensions.JsonObjectTypeSerializer.Deserialize<ProviderTypesAndAliases>(reader: reader)
                ?? throw new JsonSerializationException(message: $"Resource snapshot '{resourceName}' is null.");
        }
    }

    /// <summary>
    /// Helper class to contain the environment specific RP configuration for aliases and resource types.
    /// </summary>
    public class ProviderTypesAndAliases
    {
        /// <summary>
        /// Gets or sets the resource provider namespace
        /// </summary>
        public string Namespace { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the resource types available in the provider.
        /// </summary>
        public TypeAndAliases[] ResourceTypes { get; set; } = Array.Empty<TypeAndAliases>();
    }

    /// <summary>
    /// Helper class to contain a resource type and its alias names.
    /// </summary>
    public class TypeAndAliases
    {
        /// <summary>
        /// Gets or sets the capabilities reported by ARM, or null when unknown.
        /// </summary>
        public string? Capabilities { get; set; }

        /// <summary>
        /// Gets or sets the available aliases.
        /// </summary>
        public AliasDetails[] Aliases { get; set; } = Array.Empty<AliasDetails>();

        /// <summary>
        /// Gets or sets the name of the resource type.
        /// </summary>
        public string ResourceType { get; set; } = string.Empty;
    }

    /// <summary>
    /// Helper class to contain the details of a policy alias.
    /// </summary>
    public class AliasDetails
    {
        /// <summary>
        /// Gets or sets the alias name.
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Get or sets the alias paths.
        /// </summary>
        public AliasPath[] Paths { get; set; } = Array.Empty<AliasPath>();

        /// <summary>
        /// Gets or sets the default path metadata of the alias.
        /// </summary>
        public AliasPathMetadata DefaultMetadata { get; set; } = AliasPathMetadata.Empty;

        /// <summary>
        /// The default alias path.
        /// </summary>
        public string DefaultPath { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents the alias path.
    /// </summary>
    public class AliasPath
    {
        /// <summary>
        /// Gets or sets the alias name.
        /// </summary>
        public string Path { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the <c>api</c> version (used for control plane aliases).
        /// </summary>
        public string[] ApiVersions { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Gets or sets the alias path metadata.
        /// </summary>
        public AliasPathMetadata Metadata { get; set; } = AliasPathMetadata.Empty;
    }

    /// <summary>
    /// Represents the metadata of an alias.
    /// </summary>
    public class AliasPathMetadata
    {
        /// <summary>
        /// An instance to alias path metadata with no attributes
        /// </summary>
        public static readonly AliasPathMetadata Empty = new AliasPathMetadata() { Type = AliasPathTokenType.NotSpecified, Attributes = AliasPathAttributes.None };

        /// <summary>
        /// Gets or sets the alias path token type.
        /// </summary>
        [JsonProperty(Required = Required.Default)]
        public AliasPathTokenType Type { get; set; }

        /// <summary>
        /// Gets or sets the alias path token attributes.
        /// </summary>
        [JsonProperty(Required = Required.Default)]
        public AliasPathAttributes Attributes { get; set; }

        /// <summary>
        /// Check whether this instance equals to another instance.
        /// </summary>
        /// <param name="obj">The other instance.</param>
        public override bool Equals(object? obj)
        {
            if (obj == null || this.GetType() != obj.GetType())
            {
                return false;
            }

            var otherMetadata = (AliasPathMetadata)obj;
            return this.Type == otherMetadata.Type && this.Attributes == otherMetadata.Attributes;
        }

        /// <summary>
        /// Returns a hash code for this instance.
        /// </summary>
        public override int GetHashCode()
        {
            return this.Type.GetHashCode() ^ this.Attributes.GetHashCode();
        }
    }

#pragma warning disable CA1720

    /// <summary>
    /// The type of the token that is referred by an alias path.
    /// </summary>
    public enum AliasPathTokenType
    {
        /// <summary>
        /// The not specified token type.
        /// </summary>
        NotSpecified = 0,

        /// <summary>
        /// The any token type.
        /// </summary>
        Any,

        /// <summary>
        /// The string token type.
        /// </summary>
        String,

        /// <summary>
        /// The object token type.
        /// </summary>
        Object,

        /// <summary>
        /// The array token type.
        /// </summary>
        Array,

        /// <summary>
        /// The integer token type.
        /// </summary>
        Integer,

        /// <summary>
        /// The number token type.
        /// </summary>
        Number,

        /// <summary>
        /// The boolean token type.
        /// </summary>
        Boolean
    }

#pragma warning restore CA1720

    /// <summary>
    /// The attributes of an alias path
    /// </summary>
    [Flags]
    public enum AliasPathAttributes
    {
        /// <summary>
        /// Default attribute value.
        /// </summary>
        None = 0,

        /// <summary>
        /// The modifiable attribute.
        /// </summary>
        Modifiable = 1 << 1
    }
}
