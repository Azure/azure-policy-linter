// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects value conditions that use a logical template function.
    /// </summary>
    public sealed class LogicalFunctionsInValueConditions : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Logical Functions in Value Conditions";
        private const string RuleDescription =
            "The value condition uses the '{0}()' function, so compliance details show only the expression's final result. Use native policy conditions when they preserve the expression's behavior.";

        private static readonly OrdinalInsensitiveHashSet LogicalFunctions = new OrdinalInsensitiveHashSet
        {
            "and",
            "or",
            "not",
            "if",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="LogicalFunctionsInValueConditions"/> class.
        /// </summary>
        public LogicalFunctionsInValueConditions() : base(
            identifier: "logical-functions-in-value-conditions",
            category: Category.BestPractices,
            title: LogicalFunctionsInValueConditions.RuleTitle,
            descriptionFormat: LogicalFunctionsInValueConditions.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var value = expression.Value;
            var comparisonOperator = expression.Operator;
            if (value == null ||
                comparisonOperator == null ||
                (!comparisonOperator.Name.EqualsOrdinalInsensitively("equals") &&
                !comparisonOperator.Name.EqualsOrdinalInsensitively("notEquals")) ||
                !comparisonOperator.HasLiteralValue ||
                !bool.TryParse(comparisonOperator.Value.ToString(), out _) ||
                value.Value.Type != JTokenType.String ||
                value.LanguageExpressions.Length != 1)
            {
                return Array.Empty<LinterOutput>();
            }

            var languageExpression = value.LanguageExpressions[0];
            if (            !string.Equals(value.Value.ToString(), languageExpression.Expression, StringComparison.Ordinal) ||
            !languageExpression.TryGetFunctionName(out var functionName) ||
            !LogicalFunctionsInValueConditions.LogicalFunctions.Contains(functionName))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateInformational(value, functionName),
            };
        }
    }
}
