// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Metadata
{
    using System.Collections.Immutable;

    /// <summary>
    /// Details about a resource property.
    /// </summary>
    public class ResourcePropertyMetadata
    {
        /// <summary>
        /// The alias from which this property was resolved.
        /// </summary>
        public AliasDetails? Alias { get; set; } = null;

        /// <summary>
        /// The fully qualified resource type of the resource property.
        /// </summary>
        public string ResourceType { get; set; } = string.Empty;

        /// <summary>
        /// The resource API versions to which this metadata applies.
        /// </summary>
        public ImmutableArray<string> ApiVersions { get; set; } = ImmutableArray<string>.Empty;

        /// <summary>
        /// Whether the property exists in the API versions mentioned in <see cref="ApiVersions"/>."/>
        /// </summary>
        /// <remarks>
        /// If this is false, the properties below are not applicable.
        /// </remarks>
        public bool Exists { get; set; }

        /// <summary>
        /// The path of the property.
        /// </summary>
        public string Path { get; set; } = string.Empty;

        /// <summary>
        /// The type of the property value
        /// </summary>
        public string Type { get; set; } = string.Empty;

        /// <summary>
        /// Whether this is a readonly property.
        /// </summary>
        public bool IsReadonly { get; set; }

        /// <summary>
        /// Whether this is required.
        /// </summary>
        public bool IsRequired { get; set; }

        /// <summary>
        /// Whether this is an immutable property.
        /// </summary>
        public bool IsImmutable { get; set; }

        /// <summary>
        /// Whether this is a conditional property (i.e. it's only available if a certain condition is met).
        /// </summary>
        public bool IsConditional { get; set; }
    }
}
