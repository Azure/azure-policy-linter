// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;

    /// <summary>
    /// Policy definition resource.
    /// </summary>
    public class PolicyDefinition : PolicyExpression
    {
        /// <summary>
        /// The name of the policy definition.
        /// </summary>
        public Property? Name { get; }

        /// <summary>
        /// The policy definition properties.
        /// </summary>
        public PolicyDefinitionProperties Properties { get; private set; }

        /// <summary>
        /// Creates a new instance of the <see cref="PolicyDefinition"/> class.
        /// </summary>
        /// <param name="policyDefinition"> The policy definition.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public PolicyDefinition(
            PolicyDefinitionObject policyDefinition,
            ITypeMetadata typeMetadata)
            : base(lineNumber: 0, linePosition: 0, ImmutableArray<string>.Empty, null)
        {
            var countExpressionScopes = new Stack<CountExpressionScope>();

            this.Name = policyDefinition.Name != null
                ? new Property(
                    name: "name",
                    value: policyDefinition.Name.Value,
                    jTokenMetadata: policyDefinition.Name,
                    isFieldAccessor: false,
                    parentPath: ImmutableArray<string>.Empty,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata)
                : null;

            this.Properties = new PolicyDefinitionProperties(
                policyDefinitionPropertiesProperty: policyDefinition.Properties,
                typeMetadata: typeMetadata,
                parentPath: ImmutableArray<string>.Empty,
                parent: this);
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            if (visitor?.Visit != null)
            {
                visitor.Visit(this);
                this.Name?.Visit(visitor);
                this.Properties.Visit(visitor);
            }
        }
    }
}
