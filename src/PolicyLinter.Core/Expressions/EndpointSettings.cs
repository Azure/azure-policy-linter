// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;

    /// <summary>
    /// A policy expression that represents external evaluation endpoint settings.
    /// </summary>
    public class EndpointSettings : PolicyExpression
    {
        /// <summary>
        /// The kind of endpoint.
        /// </summary>
        public Property? Kind { get; }

        /// <summary>
        /// The endpoint details.
        /// </summary>
        public Property? Details { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="EndpointSettings"/> class.
        /// </summary>
        /// <param name="endpointSettingsProperty">The endpoint settings.</param>
        /// <param name="parentPath">The path of the parent of the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public EndpointSettings(
            GenericObjectProperty<ExternalEvaluationEndpointSettingsObject>? endpointSettingsProperty,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            ITypeMetadata typeMetadata)
            : base(
                endpointSettingsProperty?.LineNumber,
                endpointSettingsProperty?.LinePosition,
                parentPath.Add("endpointSettings"),
                parent)
        {
            var settings = endpointSettingsProperty?.Value;

            this.Kind = settings?.Kind != null
                ? new Property(
                    name: "kind",
                    value: settings.Kind.Value,
                    jTokenMetadata: settings.Kind,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: new Stack<CountExpressionScope>(),
                    typeMetadata: typeMetadata)
                : null;

            this.Details = settings?.Details != null
                ? new Property(
                    name: "details",
                    value: settings.Details.Value,
                    jTokenMetadata: settings.Details,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: new Stack<CountExpressionScope>(),
                    typeMetadata: typeMetadata)
                : null;
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            if (visitor?.Visit != null)
            {
                visitor.Visit(this);
                this.Kind?.Visit(visitor);
                this.Details?.Visit(visitor);
            }
        }
    }
}
