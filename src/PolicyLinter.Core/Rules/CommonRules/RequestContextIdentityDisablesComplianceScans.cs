// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Detects policies whose policy rule references the 'requestContext().identity' function,
    /// which the policy engine treats as NotApplicable for compliance evaluation while still
    /// enforcing effects at request time.
    /// </summary>
    public sealed class RequestContextIdentityDisablesComplianceScans : LinterRule<PolicyRule>
    {
        private const string RuleDescription =
            "The policy rule uses the 'requestContext().identity' function. Compliance results show 'NotApplicable', while enforcement effects such as Deny, DeployIfNotExists, and Modify still run at request time.";

        /// <summary>
        /// Initializes a new instance of the <see cref="RequestContextIdentityDisablesComplianceScans"/> class.
        /// </summary>
        public RequestContextIdentityDisablesComplianceScans() : base(
            identifier: "request-context-identity-disables-compliance-scans",
            category: Category.BestPractices,
            title: "Request Context Identity Disables Compliance Scans",
            descriptionFormat: RequestContextIdentityDisablesComplianceScans.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyRule expression, LinterContext context)
        {
            Reference? identityReference = null;

            var visitor = new PolicyExpressionVisitor
            {
                Visit = (visited) =>
                {
                    if (visited is Reference reference &&
                        reference.Kind == ReferenceKind.RequestContextProperty &&
                        reference.PropertySelectionPath?.Path is { Length: > 0 } path &&
                        path[0].EqualsOrdinalInsensitively("identity"))
                    {
                        identityReference ??= reference;
                    }
                }
            };

            expression.Visit(visitor);

            if (identityReference == null)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(identityReference),
            };
        }
    }
}
