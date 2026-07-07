// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

#nullable disable
namespace Microsoft.Azure.Policy.PolicyLinter.Core.Parsing
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
