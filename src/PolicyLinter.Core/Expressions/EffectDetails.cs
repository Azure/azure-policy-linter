// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using global::Azure.Deployments.Core.Exceptions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// The shape of the effect details, detected from their JSON structure (never from the effect value).
    /// </summary>
    public enum EffectDetailsKind
    {
        /// <summary>
        /// An array of field/value entries (append).
        /// </summary>
        Append,

        /// <summary>
        /// An object with 'type' (auditIfNotExists, or deployIfNotExists when 'deployment' is set).
        /// </summary>
        IfNotExists,

        /// <summary>
        /// An object with 'operations' (modify).
        /// </summary>
        Modify,

        /// <summary>
        /// An object with 'actionNames' (denyAction).
        /// </summary>
        Action,

        /// <summary>
        /// An empty object, or an object with only 'defaultState' (manual).
        /// </summary>
        Manual,
    }

    /// <summary>
    /// Represents the control-plane effect details ("then.details") of a policy rule.
    /// Holds the members of every details shape; members that are absent in the policy are null.
    /// </summary>
    public class EffectDetails : PolicyExpression
    {
        /// <summary>
        /// The shape of the details.
        /// </summary>
        public EffectDetailsKind Kind { get; }

        /// <summary>
        /// The related resource type (auditIfNotExists, deployIfNotExists).
        /// </summary>
        public Property? Type { get; }

        /// <summary>
        /// The related resource name (auditIfNotExists, deployIfNotExists).
        /// </summary>
        public Property? Name { get; }

        /// <summary>
        /// The related resource group name (auditIfNotExists, deployIfNotExists).
        /// </summary>
        public Property? ResourceGroupName { get; }

        /// <summary>
        /// The scope to look for the related resource in (auditIfNotExists, deployIfNotExists).
        /// </summary>
        public Property? ExistenceScope { get; }

        /// <summary>
        /// The delay before the related resource is evaluated (auditIfNotExists, deployIfNotExists).
        /// </summary>
        public Property? EvaluationDelay { get; }

        /// <summary>
        /// The condition evaluated against each related resource (auditIfNotExists, deployIfNotExists).
        /// Field accessors in it refer to the related resource. Field functions (e.g. "[field('name')]") refer to the resource evaluated by the 'if' condition.
        /// </summary>
        public Condition? ExistenceCondition { get; }

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
        /// The role definition IDs needed for remediation (deployIfNotExists, modify).
        /// </summary>
        public Property? RoleDefinitionIds { get; }

        /// <summary>
        /// The effect to apply on a conflict (modify).
        /// </summary>
        public Property? ConflictEffect { get; }

        /// <summary>
        /// The modify operations, or the append entries.
        /// </summary>
        public ImmutableArray<FieldOperation> Operations { get; }

        /// <summary>
        /// The actions to deny (denyAction).
        /// </summary>
        public Property? ActionNames { get; }

        /// <summary>
        /// The behavior on cascade deletion (denyAction).
        /// </summary>
        public Property? CascadeBehaviors { get; }

        /// <summary>
        /// The default compliance state (manual).
        /// </summary>
        public Property? DefaultState { get; }

        /// <summary>
        /// Creates the effect details, or returns null when the details are absent, have an unknown shape, or are malformed.
        /// </summary>
        /// <remarks>
        /// Malformed details don't fail the lint because policies with a 'disabled' effect may carry any details.
        /// </remarks>
        /// <param name="details">The raw effect details.</param>
        /// <param name="parentPath">The path of the parent of the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public static EffectDetails? TryCreate(
            GenericObjectProperty<JToken>? details,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            ITypeMetadata typeMetadata)
        {
            if (details?.Value == null || !EffectDetails.TryGetKind(details: details.Value, kind: out var kind))
            {
                return null;
            }

            try
            {
                return new EffectDetails(kind: kind, details: details, parentPath: parentPath, parent: parent, typeMetadata: typeMetadata);
            }
            catch (Exception ex) when (ex is JsonException || ex is ArgumentException || ex is ExpressionException)
            {
                return null;
            }
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);

            var properties = new[]
            {
                this.Type, this.Name, this.ResourceGroupName, this.ExistenceScope, this.EvaluationDelay, this.DeploymentScope,
                this.DeploymentParameters, this.RoleDefinitionIds, this.ConflictEffect, this.ActionNames, this.CascadeBehaviors, this.DefaultState,
            };

            foreach (var property in properties)
            {
                property?.Visit(visitor);
            }

            this.ExistenceCondition?.Visit(visitor);

            foreach (var operation in this.Operations)
            {
                operation.Visit(visitor);
            }
        }

        /// <summary>
        /// Detects the details shape the same way the policy service infers a parameterized control-plane effect.
        /// </summary>
        private static bool TryGetKind(JToken details, out EffectDetailsKind kind)
        {
            kind = EffectDetailsKind.Append;
            if (details is JArray)
            {
                return true;
            }

            if (details is not JObject detailsObject)
            {
                return false;
            }

            bool Has(string name) => detailsObject.GetValue(propertyName: name, comparison: StringComparison.OrdinalIgnoreCase) != null;

            if (Has("type"))
            {
                kind = EffectDetailsKind.IfNotExists;
            }
            else if (Has("operations"))
            {
                kind = EffectDetailsKind.Modify;
            }
            else if (Has("actionNames"))
            {
                kind = EffectDetailsKind.Action;
            }
            else if (detailsObject.Count == 0 || (detailsObject.Count == 1 && Has("defaultState")))
            {
                kind = EffectDetailsKind.Manual;
            }
            else
            {
                return false;
            }

            return true;
        }

        private EffectDetails(
            EffectDetailsKind kind,
            GenericObjectProperty<JToken> details,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(details.LineNumber, details.LinePosition, parentPath.Add("details"), parent)
        {
            this.Kind = kind;

            if (kind == EffectDetailsKind.Append)
            {
                this.Operations = details.Value
                    .ToObject<GenericObjectProperty<FieldOperationObject>[]>(jsonSerializer: PolicySerializerSettings.Serializer)!
                    .Select((entry, index) => new FieldOperation(
                        operation: entry,
                        path: parentPath.Add($"details[{index}]"),
                        parent: this,
                        typeMetadata: typeMetadata))
                    .ToImmutableArray();
                return;
            }

            var detailsObject = details.Value.ToObject<EffectDetailsObject>(jsonSerializer: PolicySerializerSettings.Serializer)!;

            Property? CreateProperty(string name, GenericObjectProperty<JToken>? property, ImmutableArray<string> propertyParentPath) => property == null
                ? null
                : new Property(
                    name: name,
                    value: property.Value,
                    jTokenMetadata: property,
                    isFieldAccessor: false,
                    parentPath: propertyParentPath,
                    parent: this,
                    countExpressionScopes: new Stack<CountExpressionScope>(),
                    typeMetadata: typeMetadata);

            this.Type = CreateProperty(name: "type", property: detailsObject.Type, propertyParentPath: this.PathSegments);
            this.Name = CreateProperty(name: "name", property: detailsObject.Name, propertyParentPath: this.PathSegments);
            this.ResourceGroupName = CreateProperty(name: "resourceGroupName", property: detailsObject.ResourceGroupName, propertyParentPath: this.PathSegments);
            this.ExistenceScope = CreateProperty(name: "existenceScope", property: detailsObject.ExistenceScope, propertyParentPath: this.PathSegments);
            this.EvaluationDelay = CreateProperty(name: "evaluationDelay", property: detailsObject.EvaluationDelay, propertyParentPath: this.PathSegments);
            this.DeploymentScope = CreateProperty(name: "deploymentScope", property: detailsObject.DeploymentScope, propertyParentPath: this.PathSegments);
            this.RoleDefinitionIds = CreateProperty(name: "roleDefinitionIds", property: detailsObject.RoleDefinitionIds, propertyParentPath: this.PathSegments);
            this.ConflictEffect = CreateProperty(name: "conflictEffect", property: detailsObject.ConflictEffect, propertyParentPath: this.PathSegments);
            this.ActionNames = CreateProperty(name: "actionNames", property: detailsObject.ActionNames, propertyParentPath: this.PathSegments);
            this.CascadeBehaviors = CreateProperty(name: "cascadeBehaviors", property: detailsObject.CascadeBehaviors, propertyParentPath: this.PathSegments);
            this.DefaultState = CreateProperty(name: "defaultState", property: detailsObject.DefaultState, propertyParentPath: this.PathSegments);

            this.ExistenceCondition = detailsObject.ExistenceCondition?.CreateCondition(
                conditionPath: this.PathSegments.Add("existenceCondition"),
                typeMetadata: typeMetadata,
                parent: this,
                countExpressionScopes: new Stack<CountExpressionScope>());

            this.Deployment = detailsObject.Deployment?.Value;
            var deploymentProperties = (this.Deployment as JObject)?.GetValue(propertyName: "properties", comparison: StringComparison.OrdinalIgnoreCase);
            var deploymentParameters = (deploymentProperties as JObject)?.GetValue(propertyName: "parameters", comparison: StringComparison.OrdinalIgnoreCase);
            this.DeploymentParameters = CreateProperty(
                name: "parameters",
                property: deploymentParameters?.ToObject<GenericObjectProperty<JToken>>(jsonSerializer: PolicySerializerSettings.Serializer),
                propertyParentPath: this.PathSegments.Add("deployment").Add("properties"));

            this.Operations = (detailsObject.Operations?.Value ?? Array.Empty<GenericObjectProperty<FieldOperationObject>>())
                .Select((operation, index) => new FieldOperation(
                    operation: operation,
                    path: this.PathSegments.Add($"operations[{index}]"),
                    parent: this,
                    typeMetadata: typeMetadata))
                .ToImmutableArray();
        }
    }
}
