// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Flags expressions that select a property beneath 'requestContext().identity' directly instead of via 'tryGet'.
    /// </summary>
    public sealed class UnguardedRequestContextIdentityAccess : LinterRule<Reference>
    {
        private const string RuleTitle = "Unguarded Request Context Identity Access";
        private const string RuleDescription =
            "A property beneath 'requestContext().identity' is selected directly (sub-property path: '{0}'). " +
            "If that path is absent from the auth token the expression fails at evaluation, which makes the policy an implicit deny. " +
            "Use 'tryGet' to select it safely.";

        private const string IdentityPropertyName = "identity";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedRequestContextIdentityAccess"/> class.
        /// </summary>
        public UnguardedRequestContextIdentityAccess() : base(
            identifier: "unguarded-request-context-identity-access",
            category: Category.BestPractices,
            title: UnguardedRequestContextIdentityAccess.RuleTitle,
            descriptionFormat: UnguardedRequestContextIdentityAccess.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Reference expression, LinterContext context)
        {
            if (expression.Kind != ReferenceKind.RequestContextProperty)
            {
                return Array.Empty<LinterOutput>();
            }

            var selectionPath = expression.PropertySelectionPath;

            // An unresolved path depends on other references, so the selected segments aren't known; a resolved path
            // that stops at 'identity' (or before) is the always-present identity object itself. Neither is a finding.
            if (selectionPath?.IsResolved != true ||
                selectionPath.Path.Length < 2 ||
                !selectionPath.Path[0].EqualsOrdinalInsensitively(UnguardedRequestContextIdentityAccess.IdentityPropertyName))
            {
                return Array.Empty<LinterOutput>();
            }

            var subPropertyPath = string.Join(".", selectionPath.Path.Skip(1));

            return new[] { this.CreateWarning(expression, subPropertyPath) };
        }
    }
}
