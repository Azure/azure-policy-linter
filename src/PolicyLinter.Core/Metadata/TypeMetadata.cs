// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Metadata
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using global::Azure.Deployments.ResourceMetadata.Contracts;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Resource type metadata.
    /// </summary>
    public class TypeMetadata : ITypeMetadata
    {
        /// <summary>
        /// The offline resource type metadata provider.
        /// </summary>
        private readonly IResourceTypeMetadataProvider metadataProvider;

        /// <summary>
        /// The alias resolver.
        /// </summary>
        private readonly IAliasResolver aliasResolver;

        /// <summary>
        /// Creates a new instance of the <see cref="TypeMetadata"/> class.
        /// </summary>
        /// <param name="metadataProvider">The metadata provider.</param>
        /// <param name="aliasResolver">The alias resolver.</param>
        public TypeMetadata(IResourceTypeMetadataProvider metadataProvider, IAliasResolver aliasResolver)
        {
            this.metadataProvider = metadataProvider;
            this.aliasResolver = aliasResolver;
        }

        /// <inheritdoc/>>
        public bool TryGetAliasPropertyMetadata(string? aliasName, out ResourcePropertyMetadata[] result)
        {
            result = Array.Empty<ResourcePropertyMetadata>();
            if (aliasName == null ||
                !this.TryResolveAlias(aliasName, out var alias)
                || alias == null)
            {
                return false;
            }

            var lst = new List<ResourcePropertyMetadata>();

            // This method is very expensive. We should run it once for all known reference instead of per-alias.
            var resourceType = FieldPathHelper.GetFieldAliasFullyQualifiedResourceType(alias.Name);
            var apiVersions = this
                .metadataProvider
                .GetApiVersionMetadataForResourceType(resourceType)
                .ToOrdinalDictionary(keySelector: a => a.ApiVersion);

            // The json paths inside the metadata are annoying:
            // - Most of them are prefixed with $[*].
            // - Conditional paths might have a complex condition inside the brackets. e.g. $[?(@.name == 'foo')].whatever.
            // This utility class helps with this mapping.
            var metadataPathMapper = new MetadataPropertyPathMapper(apiVersions);

            // For api versions that are explicitly called out in the alias, look for exact matches with the metadata.
            foreach (var aliasPath in alias.Paths.CoalesceEnumerable())
            {
                foreach (var apiVersion in aliasPath.ApiVersions)
                {
                    if (apiVersions.TryGetValue(apiVersion, out var apiVersionMetadata)
                        && apiVersionMetadata != null)
                    {
                        if (metadataPathMapper.TryGet(aliasPath.Path, apiVersion, out var metadataPropertyPath, out var isConditional)
                            && metadataPropertyPath != null
                            && apiVersionMetadata.AllPropertyPaths.TryGetValue(metadataPropertyPath, out var propertyType))
                        {
                            lst.Add(new ResourcePropertyMetadata
                            {
                                Alias = alias,
                                ResourceType = resourceType,
                                ApiVersions = new[] { apiVersion }.ToImmutableArray(),
                                Path = aliasPath.Path,
                                Exists = true,
                                Type = EnumExtensions.ToString(propertyType),
                                IsReadonly = apiVersionMetadata.ReadOnlyPropertyPaths.ContainsOrdinalInsensitively(metadataPropertyPath),
                                IsRequired = apiVersionMetadata.RequiredProperties.ContainsOrdinalInsensitively(metadataPropertyPath),
                                IsImmutable = apiVersionMetadata.ImmutablePropertyPaths.ContainsOrdinalInsensitively(metadataPropertyPath),
                                IsConditional = isConditional
                            });
                        }
                        else
                        {
                            // The alias is explicitly specifying a property path for this API version, but the metadata doesn't have it (and we DO have metadata for the API version, i.e. this version exists).
                            // This most likely means that the alias is doing something bad.
                            lst.Add(new ResourcePropertyMetadata
                            {
                                Alias = alias,
                                ResourceType = resourceType,
                                ApiVersions = new[] { apiVersion }.ToImmutableArray(),
                                Path = aliasPath.Path,
                                Exists = false
                            });
                        }

                        // Remove the metadata entry for this API version. This will make it easier for us when we process the alias's default path.
                        _ = apiVersions.Remove(apiVersion);
                    }
                }
            }

            // Now process the default path.
            // Look at all the remaining API versions in the metadata dictionary.
            foreach (var apiVersionMetadata in apiVersions.Values)
            {
                if (metadataPathMapper.TryGet(alias.DefaultPath, apiVersionMetadata.ApiVersion, out var metadataPropertyPath, out var isConditional)
                    && metadataPropertyPath != null
                    && apiVersionMetadata.AllPropertyPaths.TryGetValue(metadataPropertyPath, out var propertyType))
                {
                    lst.Add(new ResourcePropertyMetadata
                    {
                        Alias = alias,
                        ResourceType = resourceType,
                        ApiVersions = new[] { apiVersionMetadata.ApiVersion }.ToImmutableArray(),
                        Path = alias.DefaultPath,
                        Exists = true,
                        Type = EnumExtensions.ToString(propertyType),
                        IsReadonly = apiVersionMetadata.ReadOnlyPropertyPaths.ContainsOrdinalInsensitively(metadataPropertyPath),
                        IsRequired = apiVersionMetadata.RequiredProperties.ContainsOrdinalInsensitively(metadataPropertyPath),
                        IsImmutable = apiVersionMetadata.ImmutablePropertyPaths.ContainsOrdinalInsensitively(metadataPropertyPath),
                        IsConditional = isConditional
                    });
                }
                else
                {
                    lst.Add(new ResourcePropertyMetadata
                    {
                        Alias = alias,
                        ResourceType = resourceType,
                        ApiVersions = new[] { apiVersionMetadata.ApiVersion }.ToImmutableArray(),
                        Path = alias.DefaultPath,
                        Exists = false
                    });
                }
            }

            // Aggregate the results before returning.
            // Metadata with the same path and attributes (exists, type, readonly, required, immutable) are aggregated by API version.
            result = lst
                .GroupBy(propertyMetadata => new
                {
                    propertyMetadata.Alias,
                    propertyMetadata.Path,
                    propertyMetadata.Exists,
                    propertyMetadata.Type,
                    propertyMetadata.IsReadonly,
                    propertyMetadata.IsRequired,
                    propertyMetadata.IsImmutable,
                    propertyMetadata.IsConditional
                })
                .Select(group =>
                {
                    var apiVersions = group.Select(propertyMetadata => propertyMetadata.ApiVersions).SelectMany(apiVersions => apiVersions).ToImmutableArray();

                    return new ResourcePropertyMetadata
                    {
                        Alias = group.Key.Alias,
                        ResourceType = resourceType,
                        ApiVersions = apiVersions,
                        Path = group.Key.Path,
                        Exists = group.Key.Exists,
                        Type = group.Key.Type,
                        IsReadonly = group.Key.IsReadonly,
                        IsRequired = group.Key.IsRequired,
                        IsImmutable = group.Key.IsImmutable,
                        IsConditional = group.Key.IsConditional
                    };
                })
                .ToArray();

            return true;
        }

        /// <summary>
        /// Try to resolve an alias.
        /// </summary>
        /// <param name="aliasName">The alias name.</param>
        /// <param name="alias">The alias.</param>
        private bool TryResolveAlias(string aliasName, out AliasDetails? alias)
        {
            alias = null;

            // There are some aliases that span multiple resource types. e.g. Microsoft.Compute/imagePublisher.
            // We can't resolve these aliases because they depend on the evaluated resource type, which we don't have in the linter.
            if (string.IsNullOrEmpty(aliasName) || !FieldPathHelper.IsFieldAlias(aliasName) || !FieldPathHelper.FieldAliasHasFullyQualifiedResourceType(aliasName))
            {
                return false;
            }

            return this.aliasResolver.TryResolveAlias(aliasName, out alias);
        }

#pragma warning disable CA1812 // Avoid uninstantiated internal classes (no idea why the analyzer is complaining about this, also don't really care - elpere)

        private class MetadataPropertyPathMapper
        {
            private Dictionary<string, Dictionary<string, string>> propertyPathMappings = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

            public MetadataPropertyPathMapper(Dictionary<string, ResourceTypeMetadata> apiVersionMetadata)
            {
                foreach (var apiVersionToMetadata in apiVersionMetadata)
                {
                    var apiVersion = apiVersionToMetadata.Key;
                    if (apiVersion == null)
                    {
                        continue;
                    }

                    var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    this.propertyPathMappings[apiVersion] = dict;

                    var propertyPaths = apiVersionToMetadata.Value.AllPropertyPaths.Keys;
                    foreach (var propertyPath in propertyPaths)
                    {
                        if (propertyPaths == null)
                        {
                            continue;
                        }

                        var ind = propertyPath.IndexOf("].", StringComparison.OrdinalIgnoreCase);
                        if (ind > 0)
                        {
                            var pathWithoutPrefix = propertyPath.Substring(ind + 2);
                            dict[$"{apiVersion};{pathWithoutPrefix}"] = propertyPath;
                        }
                    }
                }
            }

            public bool TryGet(string path, string apiVersion, out string? metadataPropertyPath, out bool isConditional)
            {
                isConditional = false;
                if (this.propertyPathMappings.TryGetValue(apiVersion, out var dict)
                    && dict != null
                    && dict.TryGetValue($"{apiVersion};{path}", out metadataPropertyPath)
                    && metadataPropertyPath != null)
                {
                    isConditional = !metadataPropertyPath.StartsWithOrdinalInsensitively("$[*].");
                    return true;
                }
                metadataPropertyPath = null;
                return false;
            }
        }

#pragma warning restore CA1812

    }
}
