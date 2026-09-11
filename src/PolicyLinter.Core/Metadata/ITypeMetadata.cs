// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Metadata
{

    /// <summary>
    /// Interface for resource type metadata classes.
    /// </summary>
    public interface ITypeMetadata
    {
        /// <summary>
        /// Gets the capabilities of a resource type from the public-cloud snapshot.
        /// </summary>
        /// <param name="resourceType">The fully qualified resource type.</param>
        /// <param name="result">The tag and location flags, or None when the lookup fails.</param>
        /// <returns>True when capabilities are known, including an explicit None value.</returns>
        bool TryGetResourceTypeCapabilities(string? resourceType, out ResourceTypeCapabilities result);

        /// <summary>
        /// Get alias property metadata.
        /// </summary>
        /// <param name="aliasName">The alias.</param>
        /// <param name="result">The metadata for the properties referenced by the alias (if the alias was successfully resolved).</param>
        bool TryGetAliasPropertyMetadata(string? aliasName, out ResourcePropertyMetadata[] result);
    }
}
