namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Expressions;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json;

    /// <summary>
    /// The policy linter class.
    /// </summary>
    public class PolicyLinter
    {
        /// <summary>
        /// The resource type metadata container.
        /// </summary>
        private ITypeMetadata Metadata { get; }

        /// <summary>
        /// Dictionary to store rules by their target type.
        /// </summary>
        private readonly Dictionary<Type, List<ILinterRule>> rulesByTargetType = new();

        /// <summary>
        /// Creates a new instance of the <see cref="PolicyLinter"/> class with the specified rules.
        /// </summary>
        /// <param name="rules">The rules to evaluate.</param>
        /// <param name="metadata">The resource type metadata container.</param>
        public PolicyLinter(ILinterRule[] rules, ITypeMetadata metadata)
        {
            this.Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
            this.PopulateRulesDictionary(rules);
        }

        /// <summary>
        /// Lints the policy definition JSON string and returns the results of the applicable rules.
        /// </summary>
        /// <param name="rawPolicyDefinition">The raw policy definition.</param>
        /// <param name="filePath">The file path of the policy definition being linted.</param>
        public LinterOutput[] Lint(string rawPolicyDefinition, string? filePath = null)
        {
            // Validate that the file path is absolute
            if (filePath != null && !Path.IsPathRooted(filePath))
            {
                throw new ArgumentException(
                    $"Any non-null file path must be an absolute path. Empty or relative path provided: {filePath}",
                    nameof(filePath));
            }

            var results = new List<LinterOutput>();
            var context = new LinterContext(
                resourceTypeMetadata: this.Metadata,
                filePath: filePath);

            try
            {
                // Parse the policy definition and apply applicable rules
                var policyDefinition = this.ParsePolicyDefinition(rawPolicyDefinition: rawPolicyDefinition, linterOutputs: results);

                context.Parameters = policyDefinition.Properties.Parameters;
                context.ExternalEvaluationEnforcementSettings = policyDefinition.Properties.ExternalEvaluationEnforcementSettings;

                var visitor = new PolicyExpressionVisitor
                {
                    Visit = (expression) =>
                    {
                        this.ApplyRules(expression, context, results);
                    }
                };

                policyDefinition.Visit(visitor);

                return results.ToArray();
            }
            catch (LinterException ex)
            {
                results.Add(ex.Result);
                return results.ToArray();
            }
        }

        /// <summary>
        /// Populates the rules dictionary based on the provided rules.
        /// </summary>
        private void PopulateRulesDictionary(ILinterRule[] rules)
        {
            foreach (var rule in rules)
            {
                var targetType = rule.GetType().BaseType?.GetGenericArguments().FirstOrDefault();
                if (targetType != null)
                {
                    var targetTypes = rule.ApplyToDerivedTypes
                        ? targetType.Assembly.GetTypes().Where(t => t.IsSubclassOf(targetType) || t == targetType)
                        : new[] { targetType };

                    foreach (var type in targetTypes)
                    {
                        if (!this.rulesByTargetType.TryGetValue(type, out List<ILinterRule>? value))
                        {
                            value = new List<ILinterRule>();
                            this.rulesByTargetType[type] = value;
                        }

                        value.Add(rule);
                    }
                }
            }
        }

        /// <summary>
        /// Applies the rules to the given expression.
        /// </summary>
        private void ApplyRules(PolicyExpression expression, LinterContext context, List<LinterOutput> results)
        {
            var expressionType = expression.GetType();

            if (this.rulesByTargetType.TryGetValue(expressionType, out var applicableRules))
            {
                foreach (var rule in applicableRules)
                {
                    results.AddRange(rule.Evaluate(expression, context));
                }
            }
        }

        /// <summary>
        /// Parses the policy definition JSON string into a <see cref="PolicyDefinition"/> object.
        /// </summary>
        /// <param name="rawPolicyDefinition">The raw policy definition.</param>
        /// <param name="linterOutputs">The set of linter outputs that will be returned to the user.</param>
        private PolicyDefinition ParsePolicyDefinition(
            string rawPolicyDefinition,
            List<LinterOutput> linterOutputs)
        {
            try
            {
                var policyDefinitionObject = rawPolicyDefinition.FromJson<PolicyDefinitionObject>(settings: PolicySerializerSettings.Settings);
                return new PolicyDefinition(policyDefinitionObject, this.Metadata);
            }
            catch (JsonException ex)
            {
                try
                {
                    // Try to see if the provided payload is the policy definition property bag.
                    // Most (if not all) linter rules target the policy property bag and places like portal will present just the property bag.
                    // By being forgiving here we make user's life easier.
                    var policyDefinitionPropertiesObject = rawPolicyDefinition.FromJson<PolicyDefinitionPropertiesObject>(settings: PolicySerializerSettings.Settings);

                    if (policyDefinitionPropertiesObject != null)
                    {
                        linterOutputs.Add(BuiltinLinterOutputs.DetectedPolicyDefinitionPropertyBagInput());
                        var definition = new PolicyDefinitionObject
                        {
                            Properties = new GenericObjectProperty<PolicyDefinitionPropertiesObject> { Value = policyDefinitionPropertiesObject }
                        };

                        return new PolicyDefinition(definition, this.Metadata);
                    }

                }
                catch (JsonException)
                {
                }

                throw new LinterException(BuiltinLinterOutputs.PolicyDefinitionParsingFailure(parserError: ex.Message));
            }
        }
    }
}
