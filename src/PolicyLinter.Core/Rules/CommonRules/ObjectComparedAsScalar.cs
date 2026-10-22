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
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Detects object field aliases compared against a literal scalar value.
    /// </summary>
    public sealed class ObjectComparedAsScalar : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "Object Compared as Scalar";
        private const string RuleDescription =
            "The field alias: '{0}' refers to an object. The '{1}' operator does not compare the contents of the object, so the result does not depend on its properties. Reference the alias of a property in the object instead.";

        /// <summary>
        /// Initializes a new instance of the <see cref="ObjectComparedAsScalar"/> class.
        /// </summary>
        public ObjectComparedAsScalar() : base(
            identifier: "object-compared-as-scalar",
            category: Category.ResourceFields,
            title: ObjectComparedAsScalar.RuleTitle,
            descriptionFormat: ObjectComparedAsScalar.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            var field = expression.Field;
            var fieldReference = field?.FieldAccessorReference;
            var comparisonOperator = expression.Operator;
            if (field != null &&
                fieldReference != null &&
                comparisonOperator != null &&
                field.HasLiteralValue &&
                fieldReference.IsResolvedFieldReference() &&
                FieldPathHelper.IsFieldAlias(fieldReference.Identifier) &&
                (comparisonOperator.Name.EqualsOrdinalInsensitively("equals") ||
                comparisonOperator.Name.EqualsOrdinalInsensitively("notEquals")) &&
                comparisonOperator.HasLiteralValue &&
                fieldReference.ResourcePropertyMetadata.Any(
                    metadata => metadata.Exists && metadata.Type.EqualsOrdinalInsensitively("Object")))
            {
                return new[]
                {
                    this.CreateWarning(field, fieldReference.Identifier, comparisonOperator.Name),
                };
            }

            return Array.Empty<LinterOutput>();
        }
    }
}
