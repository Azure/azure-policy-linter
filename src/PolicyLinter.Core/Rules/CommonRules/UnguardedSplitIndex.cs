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
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Flags an index on the result of split() on a value known only when the policy is evaluated, outside an if() branch.
    /// </summary>
    public sealed class UnguardedSplitIndex : LinterRule<TemplateLanguageExpression>
    {
        private const string RuleTitle = "Unguarded Split Index";

        private const string RuleDescription =
            "The expression selects an element by index from the result of 'split()' on a value that is known only when the policy is evaluated. The selection fails when the value has too few segments. A failed expression makes the policy deny the request. Use 'first()' or 'last()', or check 'length()' with 'if()' first.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedSplitIndex"/> class.
        /// </summary>
        public UnguardedSplitIndex() : base(
            identifier: "unguarded-split-index",
            category: Category.BestPractices,
            title: UnguardedSplitIndex.RuleTitle,
            descriptionFormat: UnguardedSplitIndex.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            var fires = expression.FunctionCalls.Any(call =>
                !call.IsConditionallyEvaluated &&
                call.Name.EqualsOrdinalInsensitively("split") &&
                call.Selectors.Length > 0 &&
                UnguardedSplitIndex.CanBeOutOfBounds(index: call.Selectors[0]) &&
                call.ArgumentDependsOnEvaluationTimeValue(argumentIndex: 0));

            return fires
                ? new[] { this.CreateError(expression) }
                : Array.Empty<LinterOutput>();
        }

        /// <summary>
        /// Index 0 is always in bounds, because split() returns at least one element for a string, including an empty string.
        /// </summary>
        private static bool CanBeOutOfBounds(JToken? index)
        {
            return index == null || index.Type != JTokenType.Integer || index.Value<long>() != 0;
        }
    }
}