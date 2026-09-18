// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using global::Azure.Deployments.ResourceMetadata.ApiVersion;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Formatting;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;

    /// <summary>
    /// Represents API versions relevant to a field-alias finding.
    /// </summary>
    internal sealed class ApiVersionSubset
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ApiVersionSubset"/> class.
        /// </summary>
        /// <param name="kind">The subset kind.</param>
        /// <param name="apiVersions">The API versions.</param>
        /// <param name="newerAvailableApiVersionCount">The newer available API-version count.</param>
        /// <param name="newestUnavailableApiVersion">The newest unavailable API version.</param>
        private ApiVersionSubset(
            ApiVersionSubsetKind kind,
            string[] apiVersions,
            int newerAvailableApiVersionCount,
            string? newestUnavailableApiVersion)
        {
            this.Kind = kind;
            this.ApiVersions = apiVersions;
            this.NewerAvailableApiVersionCount = newerAvailableApiVersionCount;
            this.NewestUnavailableApiVersion = newestUnavailableApiVersion;
        }

        /// <summary>
        /// Gets the API versions.
        /// </summary>
        private string[] ApiVersions { get; }

        /// <summary>
        /// Gets the subset kind.
        /// </summary>
        private ApiVersionSubsetKind Kind { get; }

        /// <summary>
        /// Gets the newer available API-version count.
        /// </summary>
        private int NewerAvailableApiVersionCount { get; }

        /// <summary>
        /// Gets the newest unavailable API version.
        /// </summary>
        private string? NewestUnavailableApiVersion { get; }

        /// <summary>
        /// Determines whether another object is equal to this subset.
        /// </summary>
        /// <param name="obj">The other object.</param>
        /// <returns>Whether the objects are equal.</returns>
        public override bool Equals(object? obj)
        {
            return obj is ApiVersionSubset other &&
                this.Kind == other.Kind &&
                this.NewerAvailableApiVersionCount == other.NewerAvailableApiVersionCount &&
                string.Equals(
                    this.NewestUnavailableApiVersion,
                    other.NewestUnavailableApiVersion,
                    StringComparison.Ordinal) &&
                this.ApiVersions.SequenceEqual(
                    second: other.ApiVersions,
                    comparer: StringComparer.Ordinal);
        }

        /// <summary>
        /// Gets the structural hash code.
        /// </summary>
        /// <returns>The structural hash code.</returns>
        public override int GetHashCode()
        {
            var hashCode = new HashCode();
            hashCode.Add(this.Kind);
            hashCode.Add(this.NewerAvailableApiVersionCount);
            hashCode.Add(this.NewestUnavailableApiVersion, StringComparer.Ordinal);

            foreach (var apiVersion in this.ApiVersions)
            {
                hashCode.Add(apiVersion, StringComparer.Ordinal);
            }

            return hashCode.ToHashCode();
        }

        /// <summary>
        /// Creates an optional API-version subset.
        /// </summary>
        /// <param name="propertyMetadata">The property metadata.</param>
        /// <returns>The subset, or null when no API versions are optional.</returns>
        internal static ApiVersionSubset? CreateOptional(IEnumerable<ResourcePropertyMetadata> propertyMetadata)
        {
            var optionalApiVersions = ApiVersionSubset.NormalizeApiVersions(
                apiVersions: propertyMetadata
                    .Where(metadata => metadata.Exists && !metadata.IsRequired && !metadata.IsConditional && !metadata.IsReadonly)
                    .SelectMany(metadata => metadata.ApiVersions));

            return optionalApiVersions.Length == 0
                ? null
                : new ApiVersionSubset(
                    kind: ApiVersionSubsetKind.Optional,
                    apiVersions: optionalApiVersions,
                    newerAvailableApiVersionCount: 0,
                    newestUnavailableApiVersion: null);
        }

        /// <summary>
        /// Creates an unavailable-in-old-versions API-version subset.
        /// </summary>
        /// <param name="propertyMetadata">The property metadata.</param>
        /// <returns>The subset, or null when the latest API version is unavailable or no old versions are unavailable.</returns>
        internal static ApiVersionSubset? CreateUnavailableInOldApiVersions(
            IEnumerable<ResourcePropertyMetadata> propertyMetadata)
        {
            var metadataEntries = propertyMetadata.ToArray();
            var latestApiVersionMetadata = metadataEntries
                .MaxBy(
                    keySelector: metadata => metadata.ApiVersions.Max(comparer: SuffixAwareApiVersionComparer.Instance),
                    comparer: SuffixAwareApiVersionComparer.Instance);

            var unavailableApiVersions = ApiVersionSubset.NormalizeApiVersions(
                apiVersions: metadataEntries
                    .Where(metadata => !metadata.Exists)
                    .SelectMany(metadata => metadata.ApiVersions));

            if (latestApiVersionMetadata == null ||
                !latestApiVersionMetadata.Exists ||
                unavailableApiVersions.Length == 0)
            {
                return null;
            }

            var newestUnavailableApiVersion = unavailableApiVersions.Max(
                comparer: SuffixAwareApiVersionComparer.Instance);

            var newerAvailableApiVersionCount = metadataEntries
                .Where(metadata => metadata.Exists)
                .SelectMany(metadata => metadata.ApiVersions)
                .Distinct()
                .Count(apiVersion =>
                    SuffixAwareApiVersionComparer.Instance.Compare(
                        apiVersion,
                        newestUnavailableApiVersion) > 0);

            return new ApiVersionSubset(
                kind: ApiVersionSubsetKind.UnavailableInOldApiVersions,
                apiVersions: unavailableApiVersions,
                newerAvailableApiVersionCount: newerAvailableApiVersionCount,
                newestUnavailableApiVersion: newestUnavailableApiVersion);
        }

        /// <summary>
        /// Formats the API-version details.
        /// </summary>
        /// <returns>The API-version details.</returns>
        internal string Format()
        {
            if (this.Kind == ApiVersionSubsetKind.Optional)
            {
                return ApiVersionListFormatter.Format(apiVersions: this.ApiVersions);
            }

            var newerAvailableApiVersionText = this.NewerAvailableApiVersionCount == 1
                ? "1 newer API version"
                : $"{this.NewerAvailableApiVersionCount} newer API versions";

            return $"unavailable in {ApiVersionListFormatter.Format(apiVersions: this.ApiVersions)} (available in {newerAvailableApiVersionText})";
        }

        /// <summary>
        /// Normalizes API versions for structural comparison.
        /// </summary>
        /// <param name="apiVersions">The API versions.</param>
        /// <returns>The normalized API versions.</returns>
        private static string[] NormalizeApiVersions(IEnumerable<string> apiVersions)
        {
            return apiVersions
                .Distinct()
                .OrderBy(
                    keySelector: apiVersion => apiVersion,
                    comparer: StringComparer.Ordinal)
                .ToArray();
        }

        /// <summary>
        /// Defines API-version subset kinds.
        /// </summary>
        private enum ApiVersionSubsetKind
        {
            /// <summary>
            /// Optional API versions.
            /// </summary>
            Optional,

            /// <summary>
            /// API versions where the alias is unavailable.
            /// </summary>
            UnavailableInOldApiVersions,
        }
    }
}
