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
    /// Flags a condition whose operator value is a 'tryGet' expression. 'tryGet' returns null
    /// when the property is missing, and operator values cannot evaluate to null.
    /// </summary>
    public sealed class UnguardedTryGetOperatorValue : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Unguarded tryGet Operator Value";
        private const string RuleDescription =
            "The '{0}' operator's value is a 'tryGet(...)' expression, which returns null when the property is missing. Policy evaluation fails when an operator value evaluates to null. Wrap the expression in 'coalesce(..., <fallback>)' so the value is never null.";

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedTryGetOperatorValue"/> class.
        /// </summary>
        public UnguardedTryGetOperatorValue() : base(
            identifier: "unguarded-tryget-operator-value",
            category: Category.TemplateFunctions,
            title: UnguardedTryGetOperatorValue.RuleTitle,
            descriptionFormat: UnguardedTryGetOperatorValue.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            if (expression.Operator == null)
            {
                return Array.Empty<LinterOutput>();
            }

            if (expression.Operator.Value.Type != JTokenType.String ||
                expression.Operator.LanguageExpressions.Length != 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var valueExpression = expression.Operator.LanguageExpressions[0];
            if (!valueExpression.IsEntireValue ||
                valueExpression.Root is not TemplateFunctionCall rootCall ||
                !rootCall.Name.EqualsOrdinalInsensitively("tryGet"))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateError(expression.Operator, expression.Operator.Name),
            };
        }
    }
}
