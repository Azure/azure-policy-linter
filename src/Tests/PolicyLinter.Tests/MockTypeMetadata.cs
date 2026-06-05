// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Tests
{
    using System;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Metadata;

    /// <summary>
    /// Mock implementation of the ITypeMetadata interface for testing purposes.
    /// </summary>
    public class MockTypeMetadata : ITypeMetadata
    {
        /// <inheritdoc/>>
        public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
        {
            result = Array.Empty<ResourcePropertyMetadata>();
            return false;
        }
    }
}
