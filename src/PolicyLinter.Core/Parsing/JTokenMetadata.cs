// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Parsing
{
    /// <summary>
    /// Represents metadata for a deserialized JSON tokens
    /// </summary>
    public abstract class JTokenMetadata
    {
        /// <summary>
        /// Gets or sets the line number of token.
        /// </summary>
        public int? LineNumber { get; set; }

        /// <summary>
        /// Gets or sets the position number of token.
        /// </summary>
        public int? LinePosition { get; set; }
    }
}
