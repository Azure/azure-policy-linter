// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System;
    using System.Linq;
    using global::Azure.Deployments.ResourceMetadata.ApiVersion;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects field aliases that map to properties marked as read-only in one or more API versions of the resource type.
    /// </summary>
    public sealed class ReadOnlyFieldAlias : LinterRule<Reference>
    {
        private const string RuleTitle = "Read-Only Field Alias";
        private const string RuleDescription = "The field alias: '{0}' maps to a property that is marked as read-only in one or more API versions of resource type: '{1}'. API versions: '{2}'";

        /// <summary>
        /// Initializes a new instance of the <see cref="ReadOnlyFieldAlias"/> class.
        /// </summary>
        public ReadOnlyFieldAlias() : base(
            identifier: "read-only-field-alias",
            category: Category.ResourceFields,
            title: RuleTitle,
            descriptionFormat: RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Reference expression, LinterContext context)
        {
            if (expression.IsResolvedFieldReference() && FieldPathHelper.IsFieldAlias(expression.Identifier))
            {
                // If we have any metadata for it, it means that we successfully mapped the alias
                if (expression.ResourcePropertyMetadata.Any())
                {
                    var readonlyApiVersions = expression.ResourcePropertyMetadata
                        .Where(metadata => metadata.Exists && metadata.IsReadonly)
                        .SelectMany(metadata => metadata.ApiVersions)
                        .Distinct()
                        .OrderBy(v => v, comparer: SuffixAwareApiVersionComparer.Instance)
                        .ToArray();

                    if (readonlyApiVersions.Length != 0)
                    {
                        var resourceType = expression.ResourcePropertyMetadata.First().ResourceType;
                        var apiVersionsFormatted = string.Join(", ", readonlyApiVersions);
                        var effect = ReadOnlyFieldAlias.GetEffect(expression);

                        return new[]
                        {
                            ReadOnlyFieldAlias.IsAuditOnlyEffect(effect, context)
                                ? this.CreateInformational(expression, expression.Identifier, resourceType, apiVersionsFormatted)
                                : this.CreateWarning(expression, expression.Identifier, resourceType, apiVersionsFormatted),
                        };
                    }
                }
            }

            return Array.Empty<LinterOutput>();
        }

        /// <summary>
        /// Gets the policy effect for the reference.
        /// </summary>
        /// <param name="expression">The field reference.</param>
        /// <returns>The policy effect, or null when it is unavailable.</returns>
        private static Property? GetEffect(Reference expression)
        {
            var parent = expression.Parent;
            while (parent != null && parent is not PolicyRule)
            {
                parent = parent.Parent;
            }

            return (parent as PolicyRule)?.Then.Effect;
        }

        /// <summary>
        /// Checks whether the effect is limited to audit effects.
        /// </summary>
        /// <param name="effect">The policy effect.</param>
        /// <param name="context">The linter rule evaluation context.</param>
        /// <returns>True when the effect is limited to audit effects.</returns>
        private static bool IsAuditOnlyEffect(Property? effect, LinterContext context)
        {
            if (effect == null)
            {
                return false;
            }

            if (effect.HasLiteralValue)
            {
                return ReadOnlyFieldAlias.IsAuditEffect(effect.Value.ToStringValue());
            }

            if (effect.Value.Type != JTokenType.String ||
                effect.LanguageExpressions.Length != 1 ||
                !effect.LanguageExpressions[0].IsSimpleParameterReference(out var parameterName) ||
                context.Parameters == null ||
                !context.Parameters.TryGetValue(parameterName, out var parameter) ||
                !string.Equals(parameter.Type, PolicyParameterType.String, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var allowedValues = parameter.AllowedValues;
            if (allowedValues == null ||
                allowedValues.Length == 0 ||
                !allowedValues.All(value =>
                    value.Type == JTokenType.String &&
                    ReadOnlyFieldAlias.IsAuditEffect(value.ToStringValue())))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Checks whether a value is an audit effect.
        /// </summary>
        /// <param name="effect">The effect value.</param>
        /// <returns>True when the value is an audit effect.</returns>
        private static bool IsAuditEffect(string? effect)
        {
            return string.Equals(effect, "audit", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(effect, "auditIfNotExists", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(effect, "auditAction", StringComparison.OrdinalIgnoreCase);
        }
    }
}
