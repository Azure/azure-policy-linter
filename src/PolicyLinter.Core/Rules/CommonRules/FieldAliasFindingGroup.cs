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
    /// Represents aliases with the same API-version details.
    /// </summary>
    internal sealed class FieldAliasFindingGroup
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FieldAliasFindingGroup"/> class.
        /// </summary>
        /// <param name="aliases">The aliases.</param>
        /// <param name="apiVersionSubset">The API-version subset.</param>
        private FieldAliasFindingGroup(string[] aliases, ApiVersionSubset apiVersionSubset)
        {
            this.Aliases = aliases;
            this.ApiVersionSubset = apiVersionSubset;
        }

        /// <summary>
        /// Gets the aliases.
        /// </summary>
        internal string[] Aliases { get; }

        /// <summary>
        /// Gets the API-version subset.
        /// </summary>
        private ApiVersionSubset ApiVersionSubset { get; }

        /// <summary>
        /// Creates groups from alias details.
        /// </summary>
        /// <param name="aliasDetails">The aliases and API-version subsets.</param>
        /// <returns>The finding groups.</returns>
        internal static FieldAliasFindingGroup[] Create(
            IEnumerable<(string Alias, ApiVersionSubset ApiVersionSubset)> aliasDetails)
        {
            return aliasDetails
                .DistinctBy(
                    keySelector: item => item.Alias,
                    comparer: StringComparer.OrdinalIgnoreCase)
                .GroupBy(
                    keySelector: item => item.ApiVersionSubset)
                .Select(group => new FieldAliasFindingGroup(
                    aliases: group
                        .Select(selector: item => item.Alias)
                        .OrderBy(
                            keySelector: alias => alias,
                            comparer: StringComparer.OrdinalIgnoreCase)
                        .ToArray(),
                    apiVersionSubset: group.Key))
                .OrderBy(
                    keySelector: group => group.Aliases[0],
                    comparer: StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Formats all aliases in the group.
        /// </summary>
        /// <returns>The formatted group.</returns>
        internal string Format()
        {
            return $"'{string.Join("', '", this.Aliases)}': {this.ApiVersionSubset.Format()}";
        }

        /// <summary>
        /// Formats one alias and alias counts.
        /// </summary>
        /// <param name="totalAliasCount">The total alias count.</param>
        /// <param name="maximumLength">The maximum formatted length.</param>
        /// <param name="truncateAlias">Whether the alias can be truncated.</param>
        /// <returns>The formatted group, or null when it cannot fit.</returns>
        internal string? FormatCompact(
            int totalAliasCount,
            int maximumLength,
            bool truncateAlias)
        {
            var omittedAliasCount = this.Aliases.Length - 1;
            var sameGroupSuffix = omittedAliasCount == 0
                ? string.Empty
                : $" and {FieldAliasFindingGroup.FormatAliasCount(omittedAliasCount, "more")}";

            var otherAliasCount = totalAliasCount - this.Aliases.Length;
            var otherGroupSuffix = otherAliasCount == 0
                ? string.Empty
                : $"; and {FieldAliasFindingGroup.FormatAliasCount(otherAliasCount, "more affected")}";

            var alias = this.Aliases[0];
            var apiVersionDetails = this.ApiVersionSubset.Format();
            var formatted = $"'{alias}'{sameGroupSuffix}: {apiVersionDetails}{otherGroupSuffix}";
            if (formatted.Length <= maximumLength)
            {
                return formatted;
            }

            if (!truncateAlias)
            {
                return null;
            }

            var fixedLength = formatted.Length - alias.Length;
            var maximumAliasLength = maximumLength - fixedLength;
            if (maximumAliasLength <= 0)
            {
                return null;
            }

            alias = maximumAliasLength <= 3
                ? new string('.', maximumAliasLength)
                : $"{alias.Substring(startIndex: 0, length: maximumAliasLength - 3)}...";

            return $"'{alias}'{sameGroupSuffix}: {apiVersionDetails}{otherGroupSuffix}";
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
