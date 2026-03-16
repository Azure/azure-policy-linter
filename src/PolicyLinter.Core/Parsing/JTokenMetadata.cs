namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Parsing
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
