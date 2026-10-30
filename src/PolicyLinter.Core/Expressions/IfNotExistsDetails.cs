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
    /// The auditIfNotExists and deployIfNotExists effect details. The deployIfNotExists details are the ones with a <see cref="Deployment"/>.
    /// </summary>
    public class IfNotExistsDetails : PolicyExpression
    {
        /// <summary>
        /// The related resource type.
        /// </summary>
        public Property? Type { get; }

        /// <summary>
        /// The related resource name.
        /// </summary>
        public Property? Name { get; }

        /// <summary>
        /// The related resource group name.
        /// </summary>
        public Property? ResourceGroupName { get; }

        /// <summary>
        /// The scope to look for the related resource in.
        /// </summary>
        public Property? ExistenceScope { get; }

        /// <summary>
        /// The delay before the related resource is evaluated.
        /// </summary>
        public Property? EvaluationDelay { get; }

        /// <summary>
        /// The condition evaluated against each related resource.
        /// Field accessors in it refer to the related resource. Field functions (e.g. "[field('name')]") refer to the resource evaluated by the 'if' condition.
        /// </summary>
        public Condition? ExistenceCondition { get; }

        /// <summary>
        /// The role definition IDs needed for remediation (deployIfNotExists).
        /// </summary>
        public Property? RoleDefinitionIds { get; }

        /// <summary>
        /// The deployment scope (deployIfNotExists).
        /// </summary>
        public Property? DeploymentScope { get; }

        /// <summary>
        /// The raw deployment (deployIfNotExists). The template inside it is evaluated by ARM, not by policy, so it isn't modeled.
        /// </summary>
        public JToken? Deployment { get; }

        /// <summary>
        /// The deployment parameter values ("deployment.properties.parameters"), the only part of the deployment evaluated by policy.
        /// </summary>
        public Property? DeploymentParameters { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="IfNotExistsDetails"/> class.
        /// </summary>
        /// <param name="details">The parsed details.</param>
        /// <param name="path">The path of the details.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public IfNotExistsDetails(
            GenericObjectProperty<IfNotExistsDetailsObject> details,
            ImmutableArray<string> path,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(details.LineNumber, details.LinePosition, path, parent)
        {
            var value = details.Value;
            this.Type = value.Type.CreateProperty(name: "type", parent: this, typeMetadata: typeMetadata);
            this.Name = value.Name.CreateProperty(name: "name", parent: this, typeMetadata: typeMetadata);
            this.ResourceGroupName = value.ResourceGroupName.CreateProperty(name: "resourceGroupName", parent: this, typeMetadata: typeMetadata);
            this.ExistenceScope = value.ExistenceScope.CreateProperty(name: "existenceScope", parent: this, typeMetadata: typeMetadata);
            this.EvaluationDelay = value.EvaluationDelay.CreateProperty(name: "evaluationDelay", parent: this, typeMetadata: typeMetadata);
            this.RoleDefinitionIds = value.RoleDefinitionIds.CreateProperty(name: "roleDefinitionIds", parent: this, typeMetadata: typeMetadata);
            this.DeploymentScope = value.DeploymentScope.CreateProperty(name: "deploymentScope", parent: this, typeMetadata: typeMetadata);

            this.ExistenceCondition = value.ExistenceCondition?.CreateCondition(
                conditionPath: this.PathSegments.Add("existenceCondition"),
                typeMetadata: typeMetadata,
                parent: this,
                countExpressionScopes: new Stack<CountExpressionScope>());

            this.Deployment = value.Deployment?.Value;
            var deploymentProperties = (this.Deployment as JObject)?.GetValue(propertyName: "properties", comparison: StringComparison.OrdinalIgnoreCase);
            var deploymentParameters = (deploymentProperties as JObject)?.GetValue(propertyName: "parameters", comparison: StringComparison.OrdinalIgnoreCase);
            this.DeploymentParameters = deploymentParameters?
                .ToObject<GenericObjectProperty<JToken>>(jsonSerializer: PolicySerializerSettings.Serializer)
                .CreateProperty(
                    name: "parameters",
                    parent: this,
                    typeMetadata: typeMetadata,
                    parentPath: this.PathSegments.Add("deployment").Add("properties"));
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
            this.Type?.Visit(visitor);
            this.Name?.Visit(visitor);
            this.ResourceGroupName?.Visit(visitor);
            this.ExistenceScope?.Visit(visitor);
            this.EvaluationDelay?.Visit(visitor);
            this.ExistenceCondition?.Visit(visitor);
            this.RoleDefinitionIds?.Visit(visitor);
            this.DeploymentScope?.Visit(visitor);
            this.DeploymentParameters?.Visit(visitor);
        }
    }
}
