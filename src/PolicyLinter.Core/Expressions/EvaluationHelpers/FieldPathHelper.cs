// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions.EvaluationHelpers
{
    using System;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Extensions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Utility methods for working with field paths (as well as field aliases) in policy expressions.
    /// </summary>
    public static class FieldPathHelper
    {
        /// <summary>
        /// Returns a value indicating whether the alias references an array property
        /// </summary>
        /// <param name="fieldName">The field name.</param>
        public static bool IsArrayAlias(string fieldName)
        {
            return !fieldName.CoalesceString().StartsWithOrdinalInsensitively("tags") &&
                   fieldName.CoalesceString().Contains(Microsoft.WindowsAzure.ResourceStack.Common.Extensions.JTokenExtensions.ArrayTokenSuffix, comparisonType: StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether a given policy field name is an alias reference or a top-level property.
        /// </summary>
        /// <param name="fieldName">The field name.</param>
        public static bool IsFieldAlias(string fieldName)
        {
            return !fieldName.CoalesceString().StartsWithOrdinalInsensitively("tags") &&
                   fieldName.IsNonEmptySegmentCountLargerThanTarget(separator: '/', target: 1);
        }

        /// <summary>
        /// Whether the given alias name has enough segments to contain a fully qualified resource type
        /// </summary>
        /// <param name="aliasName">The alias name</param>
        public static bool FieldAliasHasFullyQualifiedResourceType(string aliasName)
        {
            return aliasName.IsNonEmptySegmentCountLargerThanTarget(separator: '/', target: 2);
        }

        /// <summary>
        /// Gets the left part of the alias (that should contain the fully qualified resource type if the alias is well formatted).
        /// </summary>
        /// <param name="aliasName">The alias name</param>
        public static string GetFieldAliasFullyQualifiedResourceType(string aliasName)
        {
            return aliasName[..aliasName.LastIndexOf('/')];
        }
    }
}
