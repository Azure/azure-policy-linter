namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core.Metadata
{
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Metadata;

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
