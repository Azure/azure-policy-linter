// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;

    /// <summary>
    /// An append entry ("details[i]").
    /// </summary>
    public class AppendEntry : PolicyExpression
    {
        /// <summary>
        /// The field accessor of the field to append to.
        /// </summary>
        public Property? Field { get; }

        /// <summary>
        /// The value to append.
        /// </summary>
        public Property? Value { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="AppendEntry"/> class.
        /// </summary>
        /// <param name="entry">The parsed entry.</param>
        /// <param name="path">The path of the entry.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public AppendEntry(
            GenericObjectProperty<AppendEntryObject>? entry,
            ImmutableArray<string> path,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(entry?.LineNumber, entry?.LinePosition, path, parent)
        {
            if (entry?.Value == null)
            {
                throw new ArgumentNullException(nameof(entry), "Append entry cannot be null.");
            }

            this.Field = entry.Value.Field.CreateProperty(name: "field", parent: this, typeMetadata: typeMetadata, isFieldAccessor: true);
            this.Value = entry.Value.Value.CreateProperty(name: "value", parent: this, typeMetadata: typeMetadata);
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
            this.Field?.Visit(visitor);
            this.Value?.Visit(visitor);
        }
    }
}
