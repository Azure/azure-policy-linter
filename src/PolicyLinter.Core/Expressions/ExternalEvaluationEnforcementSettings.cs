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
    /// A policy expression that represents external evaluation enforcement settings.
    /// </summary>
    public class ExternalEvaluationEnforcementSettings : PolicyExpression
    {
        /// <summary>
        /// What to do when evaluating an enforcement policy that requires an external evaluation and the token is missing.
        /// </summary>
        public Property? MissingTokenAction { get; }

        /// <summary>
        /// The lifespan of the endpoint invocation result after which it's no longer valid.
        /// </summary>
        public Property? ResultLifespan { get; }

        /// <summary>
        /// The settings of the endpoint providing the external evaluation results.
        /// </summary>
        public EndpointSettings? EndpointSettings { get; }

        /// <summary>
        /// The list of role definition Ids the assignment's MSI will need in order to invoke the endpoint.
        /// </summary>
        public Property? RoleDefinitionIds { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="ExternalEvaluationEnforcementSettings"/> class.
        /// </summary>
        /// <param name="externalEvaluationEnforcementSettingsProperty">The external evaluation enforcement settings.</param>
        /// <param name="parentPath">The path of the parent of the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public ExternalEvaluationEnforcementSettings(
            GenericObjectProperty<ExternalEvaluationEnforcementSettingsObject>? externalEvaluationEnforcementSettingsProperty,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            ITypeMetadata typeMetadata)
            : base(
                externalEvaluationEnforcementSettingsProperty?.LineNumber,
                externalEvaluationEnforcementSettingsProperty?.LinePosition,
                parentPath.Add("externalEvaluationEnforcementSettings"),
                parent)
        {
            var settings = externalEvaluationEnforcementSettingsProperty?.Value;

            this.MissingTokenAction = settings?.MissingTokenAction != null
                ? new Property(
                    name: "missingTokenAction",
                    value: settings.MissingTokenAction.Value,
                    jTokenMetadata: settings.MissingTokenAction,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: new Stack<CountExpressionScope>(),
                    typeMetadata: typeMetadata)
                : null;

            this.ResultLifespan = settings?.ResultLifespan != null
                ? new Property(
                    name: "resultLifespan",
                    value: settings.ResultLifespan.Value,
                    jTokenMetadata: settings.ResultLifespan,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: new Stack<CountExpressionScope>(),
                    typeMetadata: typeMetadata)
                : null;

            this.RoleDefinitionIds = settings?.RoleDefinitionIds != null
                ? new Property(
                    name: "roleDefinitionIds",
                    value: settings.RoleDefinitionIds.Value,
                    jTokenMetadata: settings.RoleDefinitionIds,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: new Stack<CountExpressionScope>(),
                    typeMetadata: typeMetadata)
                : null;

            this.EndpointSettings = settings?.EndpointSettings != null
                ? new EndpointSettings(
                    endpointSettingsProperty: settings.EndpointSettings,
                    parentPath: this.PathSegments,
                    parent: this,
                    typeMetadata: typeMetadata)
                : null;
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            if (visitor?.Visit != null)
            {
                visitor.Visit(this);
                this.MissingTokenAction?.Visit(visitor);
                this.ResultLifespan?.Visit(visitor);
                this.RoleDefinitionIds?.Visit(visitor);
                this.EndpointSettings?.Visit(visitor);
            }
        }
    }
}
