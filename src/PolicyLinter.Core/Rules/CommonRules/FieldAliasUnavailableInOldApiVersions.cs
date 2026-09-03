// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Detects field aliases that map to properties that exist in the latest API version but are missing in one or more older API versions of the resource type.
    /// </summary>
    public sealed class FieldAliasUnavailableInOldApiVersions : LinterRule<IfCondition>
    {
        private const string RuleTitle = "Field Alias Unavailable In Old API Versions";
        private const string RuleDescription = "Field alias API-version availability: {0}.";

        /// <summary>
        /// Initializes a new instance of the <see cref="FieldAliasUnavailableInOldApiVersions"/> class.
        /// </summary>
        public FieldAliasUnavailableInOldApiVersions() : base(
            identifier: "field-alias-unavailable-in-old-api-versions",
            category: Category.ResourceFields,
            title: FieldAliasUnavailableInOldApiVersions.RuleTitle,
            descriptionFormat: FieldAliasUnavailableInOldApiVersions.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(IfCondition expression, LinterContext context)
        {
            var affectedAliases = new List<(Reference Reference, ApiVersionSubset ApiVersionSubset)>();

            var visitor = new PolicyExpressionVisitor
            {
                Visit = visited =>
                {
                    if (visited is not Reference reference ||
                        !reference.IsResolvedFieldReference() ||
                        !FieldPathHelper.IsFieldAlias(reference.Identifier) ||
                        !reference.ResourcePropertyMetadata.Any())
                    {
                        return;
                    }

                    var apiVersionSubset = ApiVersionSubset.CreateUnavailableInOldApiVersions(
                        propertyMetadata: reference.ResourcePropertyMetadata);
                    if (apiVersionSubset == null)
                    {
                        return;
                    }

                    affectedAliases.Add((reference, apiVersionSubset));
                },
            };

            expression.Visit(visitor);

            if (affectedAliases.Count == 0)
            {
                return Array.Empty<LinterOutput>();
            }

            var maximumDetailsLength =
                FieldAliasFindingFormatter.MaximumDescriptionLength -
                string.Format(FieldAliasUnavailableInOldApiVersions.RuleDescription, string.Empty).Length;

            var groups = FieldAliasFindingGroup.Create(
                aliasDetails: affectedAliases.Select(item => (
                    Alias: item.Reference.Identifier,
                    ApiVersionSubset: item.ApiVersionSubset)));

            PolicyExpression outputExpression = groups.Sum(group => group.Aliases.Length) == 1
                ? affectedAliases[0].Reference
                : expression;

            var details = FieldAliasFindingFormatter.Format(
                groups: groups,
                maximumLength: maximumDetailsLength);

            return new[]
            {
                this.CreateWarning(outputExpression, details),
            };
        }
    }
}
