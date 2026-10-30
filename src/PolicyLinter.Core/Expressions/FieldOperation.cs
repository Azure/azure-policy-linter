// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// A write to a resource field: a modify operation ("details.operations[i]") or an append entry ("details[i]").
    /// </summary>
    public class FieldOperation : PolicyExpression
    {
        /// <summary>
        /// The operation kind, e.g. 'addOrReplace' (modify only).
        /// </summary>
        public Property? Operation { get; }

        /// <summary>
        /// The field accessor of the field to write.
        /// </summary>
        public Property? Field { get; }

        /// <summary>
        /// The value to write.
        /// </summary>
        public Property? Value { get; }

        /// <summary>
        /// The condition for applying the operation (modify only).
        /// </summary>
        public Property? Condition { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="FieldOperation"/> class.
        /// </summary>
        /// <param name="operation">The raw operation.</param>
        /// <param name="path">The path of the operation.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public FieldOperation(
            GenericObjectProperty<FieldOperationObject>? operation,
            ImmutableArray<string> path,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(operation?.LineNumber, operation?.LinePosition, path, parent)
        {
            if (operation?.Value == null)
            {
                throw new ArgumentNullException(nameof(operation), "Field operation cannot be null.");
            }

            Property? CreateProperty(string name, GenericObjectProperty<JToken>? property, bool isFieldAccessor) => property == null
                ? null
                : new Property(
                    name: name,
                    value: property.Value,
                    jTokenMetadata: property,
                    isFieldAccessor: isFieldAccessor,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: new Stack<CountExpressionScope>(),
                    typeMetadata: typeMetadata);

            this.Operation = CreateProperty(name: "operation", property: operation.Value.Operation, isFieldAccessor: false);
            this.Field = CreateProperty(name: "field", property: operation.Value.Field, isFieldAccessor: true);
            this.Value = CreateProperty(name: "value", property: operation.Value.Value, isFieldAccessor: false);
            this.Condition = CreateProperty(name: "condition", property: operation.Value.Condition, isFieldAccessor: false);
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
            this.Operation?.Visit(visitor);
            this.Field?.Visit(visitor);
            this.Value?.Visit(visitor);
            this.Condition?.Visit(visitor);
        }
    }
}
