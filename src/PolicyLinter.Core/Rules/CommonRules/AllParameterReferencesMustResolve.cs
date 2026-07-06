// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions;

    /// <summary>
    /// Checks that every parameters('...') reference in a template language expression
    /// resolves to an actual parameter defined in the policy definition.
    /// </summary>
    public sealed class AllParameterReferencesMustResolve : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "All Parameter References Must Resolve";
        private const string RuleDescription = "Found a reference to parameter '{0}', but no matching parameter definition found. Check for typos or references to removed parameters.";

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
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            if (context.Parameters == null)
            {
                return Array.Empty<LinterOutput>();
            }

            var errors = new List<LinterOutput>();

            foreach (var reference in expression.References)
            {
                if (reference.Kind != ReferenceKind.PolicyParameterName)
                {
                    continue;
                }

                if (!reference.IsResolved || string.IsNullOrEmpty(value: reference.Identifier))
                {
                    continue;
                }

                if (!context.Parameters.ContainsKey(key: reference.Identifier))
                {
                    errors.Add(this.CreateError(expression: reference, reference.Identifier));
                }
            }

            return errors.ToArray();
        }
    }
}
