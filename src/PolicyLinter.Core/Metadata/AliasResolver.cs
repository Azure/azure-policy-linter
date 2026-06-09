// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Metadata
{
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions.EvaluationHelpers;

    /// <summary>
    /// Resolves aliases.
    /// </summary>
    public interface IAliasResolver
    {
        /// <summary>
        /// Resolves an alias (if the provided string is an alias.
        /// </summary>
        /// <param name="alias">The alias.</param>
        /// <param name="resolvedAlias">The resolved alias details.</param>
        bool TryResolveAlias(string alias, out AliasDetails? resolvedAlias);
    }

    /// <inheritdoc/>
    public class AliasResolver : IAliasResolver
    {
        /// <inheritdoc/>
        public bool TryResolveAlias(string alias, out AliasDetails? resolvedAlias)
        {
            resolvedAlias = null;
            if (!FieldPathHelper.IsFieldAlias(alias) || !FieldPathHelper.FieldAliasHasFullyQualifiedResourceType(alias))
            {
                // If the alias is not a field alias or has a fully qualified resource type, we cannot resolve it
                return false;
            }

            return Aliases.GetAliases().TryGetValue(alias, out resolvedAlias);
        }
    }
}
