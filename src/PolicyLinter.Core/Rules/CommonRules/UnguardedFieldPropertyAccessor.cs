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
    /// Flags a property or index selected from a field() or current() value, outside an if() branch.
    /// </summary>
    public sealed class UnguardedFieldPropertyAccessor : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Unguarded Field Property Accessor";

        private const string RuleDescription =
            "The expression selects a property or an index from a '{0}()' value. The selection fails when the property is missing or the index is out of bounds. A failed expression makes the policy deny the request. Put the full path in the field reference, or use 'tryGet()' with 'coalesce()'.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedFieldPropertyAccessor"/> class.
        /// </summary>
        public UnguardedFieldPropertyAccessor() : base(
            identifier: "unguarded-field-property-accessor",
            category: Category.TemplateFunctions,
            title: UnguardedFieldPropertyAccessor.RuleTitle,
            descriptionFormat: UnguardedFieldPropertyAccessor.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            return !expression.IsConditionallyEvaluated &&
                expression.Selectors.Length > 0 &&
                expression.Reference != null &&
                (expression.Reference.Kind == ReferenceKind.ResourceField || expression.Reference.IsResolvedFieldReference())
                ? new[] { this.CreateError(expression, expression.Name) }
                : Array.Empty<LinterOutput>();
        }
    }
}