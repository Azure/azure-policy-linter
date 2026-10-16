// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Metadata
{
    using System;

    /// <summary>
    /// Resource type capabilities used by the linter.
    /// </summary>
    [Flags]
    public enum ResourceTypeCapabilities
    {
        /// <summary>
        /// No tag or location capability.
        /// </summary>
        None = 0,

        /// <summary>
        /// The resource type supports tags.
        /// </summary>
        SupportsTags = 1,

        /// <summary>
        /// The resource type supports location.
        /// </summary>
        SupportsLocation = 2,
    }
}
