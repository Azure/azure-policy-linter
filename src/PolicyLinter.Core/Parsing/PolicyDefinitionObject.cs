// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
namespace Microsoft.Azure.Policy.PolicyLinter.Core.Parsing
{
    using System.Collections.Generic;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    public class PolicyDefinitionObject
    {
        public GenericObjectProperty<string>? Name { get; set; }

        [JsonProperty(Required = Required.Always)]
        public GenericObjectProperty<PolicyDefinitionPropertiesObject>? Properties { get; set; }
    }

    public class PolicyDefinitionPropertiesObject
    {
        public GenericObjectProperty<string>? DisplayName { get; set; }
        public GenericObjectProperty<string>? Description { get; set; }
        public GenericObjectProperty<string>? PolicyType { get; set; }
        public GenericObjectProperty<string>? Mode { get; set; }

        [JsonProperty(Required = Required.Always)]
        public GenericObjectProperty<PolicyRuleObject>? PolicyRule { get; set; }
        public GenericObjectProperty<Dictionary<string, GenericObjectProperty<ParameterObject>>>? Parameters { get; set; }
        public GenericObjectProperty<JToken>? Metadata { get; set; }
        public GenericObjectProperty<ExternalEvaluationEnforcementSettingsObject>? ExternalEvaluationEnforcementSettings { get; set; }
        public GenericObjectProperty<string>? Version { get; set; }
    }

    public class PolicyRuleObject
    {
        [JsonProperty(Required = Required.Always)]
        public GenericObjectProperty<ConditionObject>? If { get; set; }

        [JsonProperty(Required = Required.Always)]
        public GenericObjectProperty<ThenObject>? Then { get; set; }
    }

    public class ConditionObject
    {
        public GenericObjectProperty<GenericObjectProperty<ConditionObject>[]>? AllOf { get; set; }

        public GenericObjectProperty<GenericObjectProperty<ConditionObject>[]>? AnyOf { get; set; }

        public GenericObjectProperty<GenericObjectProperty<ConditionObject>>? Not { get; set; }

        public GenericObjectProperty<JToken>? Value { get; set; }

        public GenericObjectProperty<string>? Field { get; set; }

        public GenericObjectProperty<CountObject>? Count { get; set; }

        [JsonProperty(PropertyName = "equals")]
        public GenericObjectProperty<string>? EqualsOperator { get; set; }

        public GenericObjectProperty<string>? NotEquals { get; set; }

        public GenericObjectProperty<string>? Like { get; set; }

        public GenericObjectProperty<string>? NotLike { get; set; }

        public GenericObjectProperty<JToken>? In { get; set; }

        public GenericObjectProperty<JToken>? NotIn { get; set; }

        public GenericObjectProperty<string>? Contains { get; set; }

        public GenericObjectProperty<string>? NotContains { get; set; }

        public GenericObjectProperty<string>? ContainsKey { get; set; }

        public GenericObjectProperty<string>? NotContainsKey { get; set; }

        public GenericObjectProperty<string>? Exists { get; set; }

        public GenericObjectProperty<string>? Match { get; set; }

        public GenericObjectProperty<string>? NotMatch { get; set; }

        public GenericObjectProperty<JToken>? Greater { get; set; }

        public GenericObjectProperty<JToken>? GreaterOrEquals { get; set; }

        public GenericObjectProperty<JToken>? Less { get; set; }

        public GenericObjectProperty<JToken>? LessOrEquals { get; set; }

        public GenericObjectProperty<string>? MatchInsensitively { get; set; }

        public GenericObjectProperty<string>? NotMatchInsensitively { get; set; }
    }

    public class CountObject
    {
        public GenericObjectProperty<string>? Field { get; set; }

        public GenericObjectProperty<JToken>? Value { get; set; }

        public GenericObjectProperty<string>? Name { get; set; }

        public GenericObjectProperty<ConditionObject>? Where { get; set; }
    }

    public class ParameterObject
    {
        public GenericObjectProperty<string>? Type { get; set; }
        public GenericObjectProperty<JToken>? DefaultValue { get; set; }
        public GenericObjectProperty<GenericObjectProperty<JToken>[]>? AllowedValues { get; set; }
        public GenericObjectProperty<JToken>? Metadata { get; set; }
        public GenericObjectProperty<string>? DisplayName { get; set; }
        public GenericObjectProperty<string>? Description { get; set; }
    }

    public class ThenObject
    {
        [JsonProperty(Required = Required.Always)]
        public GenericObjectProperty<string>? Effect { get; set; }

        /// <summary>
        /// The raw effect details. Kept as a token because the shape depends on the effect, and policies with
        /// a 'disabled' effect may carry any details. Object-shaped details convert to <see cref="EffectDetailsObject"/>,
        /// array-shaped (append) details convert to an array of <see cref="FieldOperationObject"/>.
        /// </summary>
        public GenericObjectProperty<JToken>? Details { get; set; }
    }

    /// <summary>
    /// The union of the members of all object-shaped control-plane effect details (auditIfNotExists, deployIfNotExists,
    /// modify, denyAction, manual). Members are tokens so that unexpected value types don't fail the conversion.
    /// </summary>
    public class EffectDetailsObject
    {
        public GenericObjectProperty<JToken>? Type { get; set; }
        public GenericObjectProperty<JToken>? Name { get; set; }
        public GenericObjectProperty<JToken>? ResourceGroupName { get; set; }
        public GenericObjectProperty<JToken>? ExistenceScope { get; set; }
        public GenericObjectProperty<JToken>? EvaluationDelay { get; set; }
        public GenericObjectProperty<ConditionObject>? ExistenceCondition { get; set; }
        public GenericObjectProperty<JToken>? DeploymentScope { get; set; }
        public GenericObjectProperty<JToken>? Deployment { get; set; }
        public GenericObjectProperty<JToken>? RoleDefinitionIds { get; set; }
        public GenericObjectProperty<JToken>? ConflictEffect { get; set; }
        public GenericObjectProperty<GenericObjectProperty<FieldOperationObject>[]>? Operations { get; set; }
        public GenericObjectProperty<JToken>? ActionNames { get; set; }
        public GenericObjectProperty<JToken>? CascadeBehaviors { get; set; }
        public GenericObjectProperty<JToken>? DefaultState { get; set; }
    }

    /// <summary>
    /// A modify operation or an append entry.
    /// </summary>
    public class FieldOperationObject
    {
        public GenericObjectProperty<JToken>? Operation { get; set; }
        public GenericObjectProperty<JToken>? Field { get; set; }
        public GenericObjectProperty<JToken>? Value { get; set; }
        public GenericObjectProperty<JToken>? Condition { get; set; }
    }

    public class ExternalEvaluationEnforcementSettingsObject
    {
        public GenericObjectProperty<string>? MissingTokenAction { get; set; }
        public GenericObjectProperty<string>? ResultLifespan { get; set; }

        [JsonProperty(Required = Required.Always)]
        public GenericObjectProperty<ExternalEvaluationEndpointSettingsObject>? EndpointSettings { get; set; }
        public GenericObjectProperty<JArray>? RoleDefinitionIds { get; set; }
    }

    public class ExternalEvaluationEndpointSettingsObject
    {
        public GenericObjectProperty<string>? Kind { get; set; }
        public GenericObjectProperty<JObject>? Details { get; set; }
    }
}
