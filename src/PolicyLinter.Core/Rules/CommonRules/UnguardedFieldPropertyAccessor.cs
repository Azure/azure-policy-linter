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
    public sealed class UnguardedFieldPropertyAccessor : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Unguarded Field Property Accessor";

        private const string RuleDescription =
            "The expression selects a property or an index from a '{0}()' value. The selection fails when the property is missing or the index is out of bounds. A failed expression makes the policy deny the request. Put the full path in the field reference, or use 'tryGet()' with 'coalesce()'.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedFieldPropertyAccessor"/> class.
        /// </summary>
        public UnguardedFieldPropertyAccessor() : base(
            identifier: "unguarded-field-property-accessor",
            category: Category.BestPractices,
            title: UnguardedFieldPropertyAccessor.RuleTitle,
            descriptionFormat: UnguardedFieldPropertyAccessor.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            var call = expression.FunctionCalls.FirstOrDefault(call =>
                !call.IsConditionallyEvaluated &&
                call.Selectors.Length > 0 &&
                call.Reference != null &&
                (call.Reference.Kind == ReferenceKind.ResourceField || call.Reference.IsResolvedFieldReference()));

            return call == null
                ? Array.Empty<LinterOutput>()
                : new[] { this.CreateError(expression, call.Name) };
        }
    }
}