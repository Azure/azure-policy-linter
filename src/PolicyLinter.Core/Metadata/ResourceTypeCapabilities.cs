// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Metadata
{
    using System;
    using System.Collections.Immutable;
    using System.Linq;

    /// <summary>
    /// Capabilities reported by ARM for a resource type.
    /// </summary>
    public class ResourceTypeCapabilities
    {
        /// <summary>
        /// Initializes resource type capabilities from the ARM capability string.
        /// </summary>
        /// <param name="capabilities">The comma-separated capability names.</param>
        public ResourceTypeCapabilities(string capabilities)
        {
            ArgumentNullException.ThrowIfNull(argument: capabilities);
            this.Tokens = capabilities
                .Split(separator: ',', options: StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .ToImmutableArray();
        }

        /// <summary>
        /// Gets the capability names, including names not interpreted by the linter.
        /// </summary>
        public ImmutableArray<string> Tokens { get; }

        /// <summary>
        /// Gets whether the resource type supports tags.
        /// </summary>
        public bool SupportsTags => this.Tokens.Contains(value: "SupportsTags", comparer: StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Gets whether the resource type supports location.
        /// </summary>
        public bool SupportsLocation => this.Tokens.Contains(value: "SupportsLocation", comparer: StringComparer.OrdinalIgnoreCase);
    }
}
