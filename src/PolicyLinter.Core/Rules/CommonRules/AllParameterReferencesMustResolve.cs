// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;

    /// <summary>
    /// Checks that every parameters('...') reference resolves to a parameter declared in the policy's parameters block.
    /// </summary>
    public sealed class AllParameterReferencesMustResolve : LinterRule<Reference>
    {
        private const string RuleTitle = "All Parameter References Must Resolve";
        private const string RuleDescription = "The parameter '{0}' is referenced but is not declared in the policy's 'parameters' block, so the reference cannot resolve.";

        /// <summary>
        /// Initializes a new instance of the <see cref="AllParameterReferencesMustResolve"/> class.
        /// </summary>
        public AllParameterReferencesMustResolve() : base(
            identifier: "all-parameter-references-must-resolve",
            category: Category.BestPractices,
            title: AllParameterReferencesMustResolve.RuleTitle,
            descriptionFormat: AllParameterReferencesMustResolve.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Reference expression, LinterContext context)
        {
            if (expression.Kind != ReferenceKind.PolicyParameterName)
            {
                return Array.Empty<LinterOutput>();
            }

            if (!expression.IsResolved || string.IsNullOrEmpty(value: expression.Identifier))
            {
                return Array.Empty<LinterOutput>();
            }

            // Emit a finding when the referenced parameter is not declared. A missing parameters block (null) counts as empty.
            if (context.Parameters?.ContainsKey(key: expression.Identifier) == true)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { this.CreateError(expression, expression.Identifier) };
        }
    }
}
