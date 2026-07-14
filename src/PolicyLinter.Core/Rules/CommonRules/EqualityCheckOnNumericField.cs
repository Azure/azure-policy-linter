// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;

    /// <summary>
    /// Flags a 'field' condition that uses 'equals' or 'notEquals' with a literal
    /// value against a field alias whose resource property is numeric. The equality
    /// operators coerce both operands to string, so a value whose string form differs
    /// from the literal (for example '5.0' versus '5') will not match.
    /// </summary>
    public sealed class EqualityCheckOnNumericField : LinterRule<LeafCondition>
    {
        private const string RuleDescription =
            "The field alias: '{0}' maps to a numeric property, but the '{1}' condition compares it against a literal value. The operator coerces both operands to string, so a value whose string form differs from the literal (for example '5.0' versus '5') will not match. Make sure the literal matches the property's canonical string form.";

        private static readonly OrdinalInsensitiveHashSet EqualityOperators = new OrdinalInsensitiveHashSet
        {
            "equals",
            "notEquals",
        };

        private static readonly OrdinalInsensitiveHashSet NumericPropertyTypes = new OrdinalInsensitiveHashSet
        {
            "Integer",
            "Number",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="EqualityCheckOnNumericField"/> class.
        /// </summary>
        public EqualityCheckOnNumericField() : base(
            identifier: "equality-check-on-numeric-field",
            category: Category.ResourceFields,
            title: "Equality Check on Numeric Field",
            descriptionFormat: EqualityCheckOnNumericField.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            if (expression.Operator == null ||
                !EqualityCheckOnNumericField.EqualityOperators.Contains(expression.Operator.Name) ||
                !expression.Operator.HasLiteralValue)
            {
                return Array.Empty<LinterOutput>();
            }

            var fieldReference = expression.Field?.FieldAccessorReference;
            if (fieldReference == null ||
                !fieldReference.IsResolvedFieldReference() ||
                !FieldPathHelper.IsFieldAlias(fieldReference.Identifier))
            {
                return Array.Empty<LinterOutput>();
            }

            var isNumeric = fieldReference.ResourcePropertyMetadata
                .Any(metadata => metadata.Exists && EqualityCheckOnNumericField.NumericPropertyTypes.Contains(metadata.Type));

            if (!isNumeric)
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateInformational(expression.Operator, fieldReference.Identifier, expression.Operator.Name),
            };
        }
    }
}
