// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Metadata
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Extensions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json;

    /// <summary>
    /// Load and stores policy aliases.
    /// </summary>
    internal static class Aliases
    {
        /// <summary>
        /// The path to the file containing resource types and aliases.
        /// </summary>
        /// <remarks>
        /// TODO:
        /// - Use the resource type metadata nuget for aliases instead of this static file.
        /// - Support multi cloud (which ironically, might force us to still have some kind of static file, but whatever)
        /// </remarks>
        private const string TypesAndAliasesFilePath = "ResourceTypesAndAliases.json";

        /// <summary>
        /// The aliases.
        /// </summary>
        private static ImmutableDictionary<string, AliasDetails> aliases = new Dictionary<string, AliasDetails>().ToImmutableDictionary();

        /// <summary>
        /// Load the aliases from the resource type metadata file (or return them from memory if already loaded).
        /// </summary>
        public static ImmutableDictionary<string, AliasDetails> GetAliases()
        {
            if (Aliases.aliases.Count == 0)
            {
                lock (Aliases.aliases)
                {
                    if (Aliases.aliases.Count == 0)
                    {
                        // TODO: this could be vastly improved:
                        // - Dynamically load aliases as they are requested.
                        // - The types json file should be an object instead of an array for faster lookups.
                        using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(TypesAndAliasesFilePath))
                        {
                            if (stream == null)
                            {
                                throw new FileNotFoundException($"The resource types and aliases were not found.");
                            }

                            using (var streamReader = new StreamReader(stream))
                            using (var reader = new JsonTextReader(streamReader))
                            {
                                var typesAndAliases = JsonExtensions.JsonObjectTypeSerializer.Deserialize<ProviderTypesAndAliases[]>(reader);
                                if (typesAndAliases != null)
                                {
                                    // TODO: There are cases of aliases for different resource types having the same name. For example: Microsoft.Compute/imagePublisher.
                                    // Current implementation will just take the last one. Need to improve this to handle such conflicts properly.
                                    // It's not high priority since such aliases are rare and are not heavily used in policies today.
                                    Aliases.aliases = typesAndAliases
                                        .SelectMany(@namespace => @namespace.ResourceTypes.SelectMany(types => types.Aliases))
                                        .ToOrdinalInsensitiveDictionary(
                                            keySelector: alias => alias.Name,
                                            elementSelector: alias => alias)
                                        .ToImmutableDictionary();
                                }
                            }
                        }
                    }
                }
            }

            return Aliases.aliases;
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
