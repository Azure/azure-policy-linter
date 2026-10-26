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
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Flags value conditions that compare the length() of an array alias to a number.
    /// </summary>
    public sealed class LengthFunctionOnArrayAlias : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Length Function on Array Alias";

        private const string RuleDescription =
            "The condition checks the length of the array field '{0}' using the length() function. Use a field count expression over '{0}' instead.";

        private static readonly OrdinalInsensitiveHashSet NumericOperators = new OrdinalInsensitiveHashSet
        {
            "equals",
            "notEquals",
            "greater",
            "greaterOrEquals",
            "less",
            "lessOrEquals",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="LengthFunctionOnArrayAlias"/> class.
        /// </summary>
        public LengthFunctionOnArrayAlias() : base(
            identifier: "length-function-on-array-alias",
            category: Category.BestPractices,
            title: LengthFunctionOnArrayAlias.RuleTitle,
            descriptionFormat: LengthFunctionOnArrayAlias.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            // Inside a count 'where', a field count over the array is either bound to the counted member or not allowed.
            if (expression.Value?.Value.Type != JTokenType.String ||
                expression.Value.LanguageExpressions.Length != 1 ||
                expression.Value.LanguageExpressions[0].References.Length != 1 ||
                expression.Operator == null ||
                !LengthFunctionOnArrayAlias.NumericOperators.Contains(expression.Operator.Name) ||
                expression.PathSegments.Any(segment => segment.EqualsOrdinalInsensitively("where")))
            {
                return Array.Empty<LinterOutput>();
            }

            var languageExpression = expression.Value.LanguageExpressions[0];
            var reference = languageExpression.References[0];
            if (reference.Kind == ReferenceKind.ResourceField &&
                reference.IsResolved &&
                reference.Identifier.EndsWith("[*]", StringComparison.Ordinal) &&
                languageExpression.Expression.EqualsOrdinalInsensitively($"[length(field('{reference.Identifier}'))]"))
            {
                return new[]
                {
                    this.CreateInformational(expression.Value, reference.Identifier),
                };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
