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
    /// Flags field count expressions with a 'where' condition that are compared to be less than the length of the same array.
    /// </summary>
    public sealed class CountLessThanArrayLength : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Count Less Than Array Length";

        private const string RuleDescription =
            "The condition checks that the number of '{0}' array members that match the 'where' condition is less than the array length. Count the array members that don't match instead, and check that the count is greater than 0.";

        /// <summary>
        /// Initializes a new instance of the <see cref="CountLessThanArrayLength"/> class.
        /// </summary>
        public CountLessThanArrayLength() : base(
            identifier: "count-less-than-array-length",
            category: Category.BestPractices,
            title: CountLessThanArrayLength.RuleTitle,
            descriptionFormat: CountLessThanArrayLength.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var arrayAlias = expression.Count?.EnumeratedArray?.FieldAccessorReference?.Identifier;
            if (arrayAlias == null ||
                expression.Count!.Where == null ||
                expression.Operator == null ||
                !expression.Operator.Name.EqualsOrdinalInsensitively("less") ||
                expression.Operator.Value.Type != JTokenType.String ||
                expression.Operator.LanguageExpressions.Length != 1 ||
                !expression.Operator.LanguageExpressions[0].Expression.EqualsOrdinalInsensitively($"[length(field('{arrayAlias}'))]"))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateInformational(expression.Operator, arrayAlias),
            };
        }
    }
}
