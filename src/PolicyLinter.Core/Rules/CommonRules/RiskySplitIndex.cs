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
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Flags an index on the result of split() on a value known only when the policy is evaluated.
    /// </summary>
    public sealed class RiskySplitIndex : LinterRule<TemplateFunctionCall>
    {
        private const string RuleTitle = "Risky Split Index";

        private const string RuleDescription =
            "The expression selects an element by index from the result of 'split()' on a value that is known only when the policy is evaluated. The selection fails when the value has too few segments, and a failed expression makes the policy deny the request. Use 'last()' or 'coalesce(first(skip(...)), <fallback>)'; they don't fail on short values.";

        /// <summary>
        /// Initializes a new instance of the <see cref="RiskySplitIndex"/> class.
        /// </summary>
        public RiskySplitIndex() : base(
            identifier: "risky-split-index",
            category: Category.TemplateFunctions,
            title: RiskySplitIndex.RuleTitle,
            descriptionFormat: RiskySplitIndex.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(TemplateFunctionCall expression, LinterContext context)
        {
            if (expression.Name.EqualsOrdinalInsensitively("split") &&
                expression.Selectors.Length > 0 &&
                RiskySplitIndex.CanBeOutOfBounds(index: expression.Selectors[0]) &&
                expression.Arguments.Length > 0 &&
                expression.Arguments[0].IsEvaluationTimeReference())
            {
                return new[] { this.CreateWarning(expression) };
            }

            return Array.Empty<LinterOutput>();
        }

        /// <summary>
        /// Index 0 is always in bounds, because split() returns at least one element for a string, including an empty string.
        /// </summary>
        private static bool CanBeOutOfBounds(TemplateLanguageNode index)
        {
            return index is not TemplateLiteralValue { Value: { Type: JTokenType.Integer } value } || value.Value<long>() != 0;
        }
    }
}
