// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Formatting
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using global::Azure.Deployments.ResourceMetadata.ApiVersion;

    /// <summary>
    /// Formats API-version lists for linter descriptions.
    /// </summary>
    public static class ApiVersionListFormatter
    {
        private const int MaximumDisplayedVersions = 2;

        /// <summary>
        /// Formats distinct API versions from newest to oldest.
        /// </summary>
        /// <param name="apiVersions">The API versions.</param>
        /// <returns>The formatted API versions.</returns>
        public static string Format(IEnumerable<string> apiVersions)
        {
            ArgumentNullException.ThrowIfNull(apiVersions);

            var versions = apiVersions
                .Distinct()
                .OrderByDescending(
                    version => version,
                    comparer: SuffixAwareApiVersionComparer.Instance)
                .ToArray();

            if (versions.Length <= ApiVersionListFormatter.MaximumDisplayedVersions)
            {
                return string.Join(", ", versions);
            }

            var omittedVersionCount = versions.Length - ApiVersionListFormatter.MaximumDisplayedVersions;
            var omittedVersionText = omittedVersionCount == 1
                ? "1 older API version"
                : $"{omittedVersionCount} older API versions";

            return $"{string.Join(", ", versions.Take(ApiVersionListFormatter.MaximumDisplayedVersions))}, and {omittedVersionText}";
        }
    }
}
