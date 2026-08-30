// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using global::Azure.Deployments.ResourceMetadata.ApiVersion;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Formatting;
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
            var affectedAliases = new Dictionary<string, (Reference Reference, string GroupKey, string ApiVersionDetails)>(StringComparer.OrdinalIgnoreCase);

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

                    var latestApiVersionMetadata = reference.ResourcePropertyMetadata
                        .MaxBy(
                            keySelector: metadata => metadata.ApiVersions.Max(comparer: SuffixAwareApiVersionComparer.Instance),
                            comparer: SuffixAwareApiVersionComparer.Instance);

                    var apiVersionsWithoutProperty = reference.ResourcePropertyMetadata
                        .Where(metadata => !metadata.Exists)
                        .SelectMany(metadata => metadata.ApiVersions)
                        .ToArray();

                    if (latestApiVersionMetadata == null ||
                        !latestApiVersionMetadata.Exists ||
                        apiVersionsWithoutProperty.Length == 0)
                    {
                        return;
                    }

                    var newestUnavailableApiVersion = apiVersionsWithoutProperty.Max(
                        comparer: SuffixAwareApiVersionComparer.Instance);

                    var newerAvailableApiVersionCount = reference.ResourcePropertyMetadata
                        .Where(metadata => metadata.Exists)
                        .SelectMany(metadata => metadata.ApiVersions)
                        .Distinct()
                        .Count(apiVersion =>
                            SuffixAwareApiVersionComparer.Instance.Compare(
                                apiVersion,
                                newestUnavailableApiVersion) > 0);

                    var newerAvailableApiVersionText = newerAvailableApiVersionCount == 1
                        ? "1 newer API version"
                        : $"{newerAvailableApiVersionCount} newer API versions";

                    var groupKey = string.Join(
                        ", ",
                        apiVersionsWithoutProperty
                            .Distinct()
                            .OrderBy(apiVersion => apiVersion, StringComparer.Ordinal)) +
                        $"|{newerAvailableApiVersionCount}";

                    _ = affectedAliases.TryAdd(
                        key: reference.Identifier,
                        value: (
                            reference,
                            groupKey,
                            $"unavailable in {ApiVersionListFormatter.Format(apiVersionsWithoutProperty)} (available in {newerAvailableApiVersionText})"));
                },
            };

            expression.Visit(visitor);

            if (affectedAliases.Count == 0)
            {
                return Array.Empty<LinterOutput>();
            }

            PolicyExpression outputExpression = affectedAliases.Count == 1
                ? affectedAliases.Values.First().Reference
                : expression;

            var maximumDetailsLength =
                FieldAliasFindingFormatter.MaximumDescriptionLength -
                string.Format(FieldAliasUnavailableInOldApiVersions.RuleDescription, string.Empty).Length;

            var groups = FieldAliasFindingGroup.Create(
                aliasDetails: affectedAliases.Select(item => (
                    Alias: item.Key,
                    GroupKey: item.Value.GroupKey,
                    ApiVersionDetails: item.Value.ApiVersionDetails)));

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
