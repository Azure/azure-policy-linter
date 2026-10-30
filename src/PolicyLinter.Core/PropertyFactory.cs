// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core
{
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Extensions for <see cref="GenericObjectProperty{JToken}"/> to create <see cref="Property"/> expressions outside of conditions.
    /// </summary>
    internal static class PropertyFactory
    {
        /// <summary>
        /// Creates a property expression, or returns null when the property is absent.
        /// </summary>
        /// <param name="property">The parsed property.</param>
        /// <param name="name">The property name.</param>
        /// <param name="parent">The parent expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        /// <param name="isFieldAccessor">Whether the property value is a field accessor.</param>
        /// <param name="parentPath">The path of the parent. Defaults to the path of <paramref name="parent"/>.</param>
        internal static Property? CreateProperty(
            this GenericObjectProperty<JToken>? property,
            string name,
            PolicyExpression parent,
            ITypeMetadata typeMetadata,
            bool isFieldAccessor = false,
            ImmutableArray<string>? parentPath = null)
        {
            return property == null
                ? null
                : new Property(
                    name: name,
                    value: property.Value,
                    jTokenMetadata: property,
                    isFieldAccessor: isFieldAccessor,
                    parentPath: parentPath ?? parent.PathSegments,
                    parent: parent,
                    countExpressionScopes: new Stack<CountExpressionScope>(),
                    typeMetadata: typeMetadata);
        }
    }
}
