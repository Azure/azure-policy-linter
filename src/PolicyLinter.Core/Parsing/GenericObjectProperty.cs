#nullable disable
namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Parsing
{
    /// <summary>
    /// Represents a deserialized JSON token with generic type metadata.
    /// </summary>
    public class GenericObjectProperty<T> : JTokenMetadata
    {
        /// <summary>
        /// Gets or sets value.
        /// </summary>
        public T Value { get; set; }
    }
}
