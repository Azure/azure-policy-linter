namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Tests
{
    using System;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Metadata;

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
