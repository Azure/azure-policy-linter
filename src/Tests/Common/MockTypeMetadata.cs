// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;

    /// <summary>
    /// Mock implementation of the ITypeMetadata interface for testing purposes.
    /// </summary>
    public class MockTypeMetadata : ITypeMetadata
    {
        /// <summary>
        /// Known capabilities, keyed case-insensitively by fully qualified resource type.
        /// </summary>
        public Dictionary<string, ResourceTypeCapabilities> Capabilities { get; } = new(comparer: StringComparer.OrdinalIgnoreCase);

        /// <inheritdoc/>
        public bool TryGetResourceTypeCapabilities(string resourceType, out ResourceTypeCapabilities result)
        {
            result = ResourceTypeCapabilities.None;
            return resourceType != null && this.Capabilities.TryGetValue(key: resourceType, value: out result);
        }

        /// <inheritdoc/>>
        public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
        {
            result = Array.Empty<ResourcePropertyMetadata>();
            return false;
        }
    }
}
