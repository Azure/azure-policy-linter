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
