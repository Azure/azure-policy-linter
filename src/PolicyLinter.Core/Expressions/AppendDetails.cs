// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System.Collections.Immutable;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;

    /// <summary>
    /// The append effect details: an array of field/value entries.
    /// </summary>
    public class AppendDetails : PolicyExpression
    {
        /// <summary>
        /// The append entries.
        /// </summary>
        public ImmutableArray<AppendEntry> Entries { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="AppendDetails"/> class.
        /// </summary>
        /// <param name="details">The parsed details.</param>
        /// <param name="path">The path of the details.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public AppendDetails(
            GenericObjectProperty<GenericObjectProperty<AppendEntryObject>[]> details,
            ImmutableArray<string> path,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(details.LineNumber, details.LinePosition, path, parent)
        {
            // The details are the array, so entries are indexed on the 'details' segment itself (e.g. 'then.details[0]').
            this.Entries = details.Value
                .Select((entry, index) => new AppendEntry(
                    entry: entry,
                    path: this.PathSegments.RemoveAt(index: this.PathSegments.Length - 1).Add($"details[{index}]"),
                    parent: this,
                    typeMetadata: typeMetadata))
                .ToImmutableArray();
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);

            foreach (var entry in this.Entries)
            {
                entry.Visit(visitor);
            }
        }
    }
}
