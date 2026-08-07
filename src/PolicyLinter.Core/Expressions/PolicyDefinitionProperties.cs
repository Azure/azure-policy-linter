// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// A policy expression that represents a parsed policy definition.
    /// </summary>
    public class PolicyDefinitionProperties : PolicyExpression
    {
        /// <summary>
        /// The display name of the policy definition.
        /// </summary>
        public Property? DisplayName { get; }

        /// <summary>
        /// The description of the policy definition.
        /// </summary>
        public Property? Description { get; }

        /// <summary>
        /// The policy type of the policy definition.
        /// </summary>
        public Property? PolicyType { get; }

        /// <summary>
        /// The mode of the policy definition.
        /// </summary>
        public Property? Mode { get; }

        /// <summary>
        /// The policy rule expression.
        /// </summary>
        public PolicyRule PolicyRule { get; }

        /// <summary>
        /// The parameters of the policy definition.
        /// </summary>
        public ImmutableDictionary<string, Parameter>? Parameters { get; }

        /// <summary>
        /// The metadata of the policy definition.
        /// </summary>
        public Property? Metadata { get; }

        /// <summary>
        /// The version of the policy definition.
        /// </summary>
        public Property? Version { get; }

        /// <summary>
        /// The external evaluation enforcement settings of the policy definition.
        /// </summary>
        public ExternalEvaluationEnforcementSettings? ExternalEvaluationEnforcementSettings { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="PolicyDefinitionProperties"/> class.
        /// </summary>
        /// <param name="policyDefinitionPropertiesProperty">The policy definition properties.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        /// <param name="parentPath">The path of the parent of the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        public PolicyDefinitionProperties(
            GenericObjectProperty<PolicyDefinitionPropertiesObject>? policyDefinitionPropertiesProperty,
            ITypeMetadata typeMetadata,
            ImmutableArray<string> parentPath,
            PolicyExpression parent)
            : base(policyDefinitionPropertiesProperty?.LineNumber, policyDefinitionPropertiesProperty?.LinePosition, parentPath.Concat("properties").ToImmutableArray(), parent)
        {
            var policyDefinitionProperties = policyDefinitionPropertiesProperty?.Value;
            var countExpressionScopes = new Stack<CountExpressionScope>();

            this.DisplayName = policyDefinitionProperties?.DisplayName != null
                ? new Property(
                    name: "displayName",
                    value: policyDefinitionProperties.DisplayName.Value,
                    jTokenMetadata: policyDefinitionProperties.DisplayName,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata)
                : null;

            this.Description = policyDefinitionProperties?.Description != null
                ? new Property(
                    name: "description",
                    value: policyDefinitionProperties.Description.Value,
                    jTokenMetadata: policyDefinitionProperties.Description,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata)
                : null;

            this.PolicyType = policyDefinitionProperties?.PolicyType != null
                ? new Property(
                    name: "policyType",
                    value: policyDefinitionProperties.PolicyType.Value,
                    jTokenMetadata: policyDefinitionProperties.PolicyType,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata)
                : null;

            this.Mode = policyDefinitionProperties?.Mode != null
                ? new Property(
                    name: "mode",
                    value: policyDefinitionProperties.Mode.Value,
                    jTokenMetadata: policyDefinitionProperties.Mode,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata)
                : null;

            this.Metadata = policyDefinitionProperties?.Metadata != null
                ? new Property(
                    name: "metadata",
                    value: policyDefinitionProperties.Metadata.Value,
                    jTokenMetadata: policyDefinitionProperties.Metadata,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata)
                : null;

            this.Version = policyDefinitionProperties?.Version != null
                ? new Property(
                    name: "version",
                    value: policyDefinitionProperties.Version.Value,
                    jTokenMetadata: policyDefinitionProperties.Version,
                    isFieldAccessor: false,
                    parentPath: this.PathSegments,
                    parent: this,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata)
                : null;

            this.ExternalEvaluationEnforcementSettings = policyDefinitionProperties?.ExternalEvaluationEnforcementSettings != null
                ? new ExternalEvaluationEnforcementSettings(
                    externalEvaluationEnforcementSettingsProperty: policyDefinitionProperties.ExternalEvaluationEnforcementSettings,
                    parentPath: this.PathSegments,
                    parent: this,
                    typeMetadata: typeMetadata)
                : null;

            this.PolicyRule = new PolicyRule(
                policyRuleProperty: policyDefinitionProperties?.PolicyRule,
                parentPath: this.PathSegments,
                parent: parent,
                typeMetadata: typeMetadata);

            var parametersPaths = this.PathSegments.Concat("parameters").ToImmutableArray();
            this.Parameters = policyDefinitionProperties?.Parameters?.Value.ToDictionary(
                    keySelector: kvp => kvp.Key,
                    elementSelector: kvp => new Parameter(name: kvp.Key, parameterProperty: kvp.Value, path: parametersPaths.Concat(kvp.Key).ToImmutableArray(), parent: parent))
                .ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            if (visitor?.Visit != null)
            {
                visitor.Visit(this);

                this.DisplayName?.Visit(visitor);
                this.Description?.Visit(visitor);
                this.PolicyType?.Visit(visitor);
                this.Mode?.Visit(visitor);
                this.Metadata?.Visit(visitor);
                this.Version?.Visit(visitor);

                this.PolicyRule.Visit(visitor);

                if (this.Parameters != null)
                {
                    foreach (var parameter in this.Parameters.Values)
                    {
                        parameter.Visit(visitor);
                    }
                }

                this.ExternalEvaluationEnforcementSettings?.Visit(visitor);
            }
        }
    }
}
