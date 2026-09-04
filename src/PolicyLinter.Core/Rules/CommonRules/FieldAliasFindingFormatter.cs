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
        /// Formats field-alias groups.
        /// </summary>
        /// <param name="groups">The field-alias groups.</param>
        /// <param name="maximumLength">The maximum formatted length.</param>
        /// <returns>The formatted alias details.</returns>
        internal static string Format(
            IEnumerable<FieldAliasFindingGroup> groups,
            int maximumLength)
        {
            var orderedGroups = groups.ToArray();

            var formattedGroups = orderedGroups
                .Select(group => group.Format())
                .ToArray();

            var fullDetails = string.Join("; ", formattedGroups);
            if (fullDetails.Length <= maximumLength)
            {
                return fullDetails;
            }

            var totalAliasCount = orderedGroups.Sum(group => group.Aliases.Length);
            foreach (var group in orderedGroups)
            {
                var compactDetails = group.FormatCompact(
                    totalAliasCount: totalAliasCount,
                    maximumLength: maximumLength,
                    truncateAlias: false);
                if (compactDetails != null)
                {
                    return compactDetails;
                }
            }

            foreach (var group in orderedGroups)
            {
                var compactDetails = group.FormatCompact(
                    totalAliasCount: totalAliasCount,
                    maximumLength: maximumLength,
                    truncateAlias: true);
                if (compactDetails != null)
                {
                    return compactDetails;
                }
            }

            var aliasLabel = totalAliasCount == 1
                ? "alias"
                : "aliases";
            var aliasCount = $"{totalAliasCount} affected {aliasLabel}";
            return aliasCount.Length <= maximumLength
                ? aliasCount
                : aliasCount.Substring(startIndex: 0, length: Math.Max(0, maximumLength));
        }
    }
}
