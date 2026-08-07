// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using global::Azure.Deployments.Expression.Engines;
    using global::Azure.Deployments.Expression.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Flags substring calls on resource values that are not guarded against an input
    /// shorter than the requested range.
    /// </summary>
    public sealed class UnguardedSubstringOnResourceValue : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Unguarded Substring on Resource Value";

        private const string RuleDescription =
            "The condition calls 'substring' on a resource value without checking its length first. When the value is shorter than the requested range the expression fails, and a failed expression makes the policy deny the request. Guard the call with 'if()' and 'length()'.";

        /// <summary>
        /// The functions that return a value with the same length as their input, so a resource
        /// value wrapped in one of them is still of unknown length.
        /// </summary>
        private static readonly OrdinalInsensitiveHashSet LengthPreservingFunctions = new OrdinalInsensitiveHashSet
        {
            "toLower",
            "toUpper",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="UnguardedSubstringOnResourceValue"/> class.
        /// </summary>
        public UnguardedSubstringOnResourceValue() : base(
            identifier: "unguarded-substring-on-resource-value",
            category: Category.BestPractices,
            title: UnguardedSubstringOnResourceValue.RuleTitle,
            descriptionFormat: UnguardedSubstringOnResourceValue.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var outputs = new List<LinterOutput>();

            foreach (var property in new[] { expression.Value, expression.Operator })
            {
                if (property != null &&
                    property.LanguageExpressions.Any(languageExpression =>
                        UnguardedSubstringOnResourceValue.ContainsUnguardedSubstring(
                            expression: ExpressionsEngine.ParseLanguageExpression(languageExpression.Expression),
                            references: languageExpression.References)))
                {
                    outputs.Add(this.CreateError(expression: property));
                }
            }

            return outputs.ToArray();
        }

        /// <summary>
        /// Searches an expression for a substring call on a resource value with fixed bounds.
        /// An 'if' is the documented guard for this pattern, so its contents are not searched.
        /// </summary>
        private static bool ContainsUnguardedSubstring(
            LanguageExpression expression,
            ImmutableArray<Reference> references)
        {
            if (expression is not FunctionExpression function ||
                string.Equals(function.Function, "if", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return UnguardedSubstringOnResourceValue.IsUnguardedSubstringCall(
                    function: function,
                    references: references) ||
                function.Parameters.Any(parameter =>
                    UnguardedSubstringOnResourceValue.ContainsUnguardedSubstring(
                        expression: parameter,
                        references: references));
        }

        private static bool IsUnguardedSubstringCall(
            FunctionExpression function,
            ImmutableArray<Reference> references)
        {
            if (!string.Equals(function.Function, "substring", StringComparison.OrdinalIgnoreCase) ||
                function.Parameters.Length != 3 ||
                !UnguardedSubstringOnResourceValue.IsResourceValueReference(
                    expression: function.Parameters[0],
                    references: references))
            {
                return false;
            }

            return UnguardedSubstringOnResourceValue.TryGetNonnegativeIntegerLiteral(function.Parameters[1], out var start) &&
                UnguardedSubstringOnResourceValue.TryGetNonnegativeIntegerLiteral(function.Parameters[2], out var length) &&
                !(start == 0 && length == 0);
        }

        /// <summary>
        /// Determines whether the substring input is a resource value whose length is unknown.
        /// Only a bare 'field' or 'current' reference qualifies, optionally wrapped in functions
        /// that preserve the input length. Any other wrapping function can change the length in
        /// ways this rule cannot reason about.
        /// </summary>
        private static bool IsResourceValueReference(
            LanguageExpression expression,
            ImmutableArray<Reference> references)
        {
            if (expression is not FunctionExpression function)
            {
                return false;
            }

            if (string.Equals(function.Function, "field", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (string.Equals(function.Function, "current", StringComparison.OrdinalIgnoreCase))
            {
                return references.Any(reference =>
                    reference.Kind == ReferenceKind.CurrentArrayMember &&
                    reference.IsResolvedFieldReference());
            }

            return UnguardedSubstringOnResourceValue.LengthPreservingFunctions.Contains(function.Function) &&
                function.Parameters.Length == 1 &&
                UnguardedSubstringOnResourceValue.IsResourceValueReference(
                    expression: function.Parameters[0],
                    references: references);
        }

        private static bool TryGetNonnegativeIntegerLiteral(LanguageExpression expression, out long value)
        {
            value = 0;

            if (expression is not JTokenExpression literal ||
                literal.Value.Type != JTokenType.Integer ||
                literal.Value is not JValue tokenValue ||
                tokenValue.Value is not long integerValue ||
                integerValue < 0)
            {
                return false;
            }

            value = integerValue;
            return true;
        }
    }
}
