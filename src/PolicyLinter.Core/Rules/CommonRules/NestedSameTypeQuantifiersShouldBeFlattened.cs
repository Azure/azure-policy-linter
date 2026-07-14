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
        private const string RuleTitle = "Nested Same-Type Quantifiers Should Be Flattened";

        private const string RuleDescription =
            "This '{0}' quantifier is nested inside a parent '{0}' and can be flattened into it.";

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
            // Only fire when the parent quantifier has more than one child, so that flattening the
            // nested quantifier merges its children into existing siblings.
            if (expression.AllOf != null && expression.AllOf.Value.Length >= 2)
            {
                return this.FindNestedQuantifiers(
                    children: expression.AllOf.Value,
                    isSameType: nested => nested.AllOf != null && nested.AllOf.Value.Length >= 2,
                    quantifierName: "allOf");
            }

            if (expression.AnyOf != null && expression.AnyOf.Value.Length >= 2)
            {
                return this.FindNestedQuantifiers(
                    children: expression.AnyOf.Value,
                    isSameType: nested => nested.AnyOf != null && nested.AnyOf.Value.Length >= 2,
                    quantifierName: "anyOf");
            }

            return Array.Empty<LinterOutput>();
        }

        private LinterOutput[] FindNestedQuantifiers(
            ImmutableArray<Condition> children,
            Func<Quantifier, bool> isSameType,
            string quantifierName)
        {
            var outputs = new List<LinterOutput>();

            for (int i = 0; i < children.Length; i++)
            {
                if (children[i] is Quantifier nested && isSameType(nested))
                {
                    outputs.Add(this.CreateInformational(expression: nested, quantifierName));
                }
            }

            return outputs.ToArray();
        }
    }
}
