// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Formats aggregated field-alias findings.
    /// </summary>
    internal static class FieldAliasFindingFormatter
    {
        internal const int MaximumDescriptionLength = 400;

        /// <summary>
        /// Formats aliases grouped by identical API-version details.
        /// </summary>
        /// <param name="aliasDetails">One or more aliases, grouping keys, and API-version details.</param>
        /// <param name="maximumLength">The maximum formatted length.</param>
        /// <returns>The formatted alias details.</returns>
        internal static string Format(
            IEnumerable<(string Alias, string GroupKey, string ApiVersionDetails)> aliasDetails,
            int maximumLength)
        {
            var groups = aliasDetails
                .GroupBy(
                    item => item.GroupKey,
                    StringComparer.Ordinal)
                .Select(group => (
                    ApiVersionDetails: group.First().ApiVersionDetails,
                    Aliases: group
                        .Select(item => item.Alias)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(alias => alias, StringComparer.OrdinalIgnoreCase)
                        .ToArray()))
                .OrderBy(group => group.Aliases[0], StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var formattedGroups = groups
                .Select(group =>
                    $"'{string.Join("', '", group.Aliases)}': {group.ApiVersionDetails}")
                .ToArray();

            var fullDetails = string.Join("; ", formattedGroups);
            if (fullDetails.Length <= maximumLength)
            {
                return fullDetails;
            }

            var firstGroup = groups[0];
            var omittedFromFirstGroup = firstGroup.Aliases.Length - 1;
            var firstAliasText = omittedFromFirstGroup == 0
                ? $"'{firstGroup.Aliases[0]}'"
                : $"'{firstGroup.Aliases[0]}' and {FieldAliasFindingFormatter.FormatAliasCount(omittedFromFirstGroup, "more")}";

            var remainingAliasCount = groups
                .Skip(1)
                .Sum(group => group.Aliases.Length);

            var compactDetails = $"{firstAliasText}: {firstGroup.ApiVersionDetails}";
            if (remainingAliasCount != 0)
            {
                compactDetails += $"; and {FieldAliasFindingFormatter.FormatAliasCount(remainingAliasCount, "more affected")}";
            }

            if (compactDetails.Length <= maximumLength)
            {
                return compactDetails;
            }

            var totalAliasCount = groups.Sum(group => group.Aliases.Length);
            return FieldAliasFindingFormatter.FormatAliasCount(totalAliasCount, "affected");
        }

        /// <summary>
        /// Formats an alias count.
        /// </summary>
        /// <param name="count">The alias count.</param>
        /// <param name="modifier">The alias modifier.</param>
        /// <returns>The formatted alias count.</returns>
        private static string FormatAliasCount(int count, string modifier)
        {
            var aliasLabel = count == 1
                ? "alias"
                : "aliases";

            return $"{count} {modifier} {aliasLabel}";
        }
    }
}
