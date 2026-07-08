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
        /// Get alias property metadata.
        /// </summary>
        /// <param name="aliasName">The alias.</param>
        /// <param name="result">The metadata for the properties referenced by the alias (if the alias was successfully resolved).</param>
        bool TryGetAliasPropertyMetadata(string? aliasName, out ResourcePropertyMetadata[] result);
    }
}
