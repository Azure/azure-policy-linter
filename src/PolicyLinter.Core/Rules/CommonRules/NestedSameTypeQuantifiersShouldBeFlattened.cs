// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Detects nested quantifiers of the same type (allOf inside allOf, or anyOf inside anyOf)
    /// that can be flattened into the outer quantifier.
    /// </summary>
    public sealed class NestedSameTypeQuantifiersShouldBeFlattened : LinterRule<Quantifier>
    {
        private const string RuleTitle = "Nested same-type quantifiers should be flattened";

        private const string RuleDescription =
            "This \"{0}\" quantifier is nested inside a parent \"{0}\" and can be flattened into it.";

        /// <summary>
        /// Initializes a new instance of the <see cref="NestedSameTypeQuantifiersShouldBeFlattened"/> class.
        /// </summary>
        public NestedSameTypeQuantifiersShouldBeFlattened() : base(
            identifier: "nested-same-type-quantifiers-should-be-flattened",
            category: Category.BestPractices,
            title: NestedSameTypeQuantifiersShouldBeFlattened.RuleTitle,
            descriptionFormat: NestedSameTypeQuantifiersShouldBeFlattened.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Quantifier expression, LinterContext context)
        {
            if (expression.AllOf != null)
            {
                return this.FindNestedQuantifiers(
                    children: expression.AllOf.Value,
                    quantifierName: "allOf");
            }

            if (expression.AnyOf != null)
            {
                return this.FindNestedQuantifiers(
                    children: expression.AnyOf.Value,
                    quantifierName: "anyOf");
            }

            return Array.Empty<LinterOutput>();
        }

        private LinterOutput[] FindNestedQuantifiers(
            ImmutableArray<Condition> children,
            string quantifierName)
        {
            var warnings = new List<LinterOutput>();

            for (int i = 0; i < children.Length; i++)
            {
                if (children[i] is Quantifier nested)
                {
                    bool isNestedSameType = quantifierName == "allOf"
                        ? nested.AllOf != null
                        : nested.AnyOf != null;

                    if (isNestedSameType)
                    {
                        warnings.Add(this.CreateWarning(expression: nested, quantifierName));
                    }
                }
            }

            return warnings.ToArray();
        }
    }
}
