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

    /// <summary>
    /// Flags policies whose 'if' condition checks only the resource type. With effects that use the type conditions
    /// to decide applicability, such a policy never reports a resource as compliant.
    /// </summary>
    public sealed class TypeOnlyIfCondition : LinterRule<PolicyRule>
    {
        private const string RuleTitle = "Type-Only If Condition";

        private const string RuleDescription =
            "The policy's 'if' condition checks only the resource 'type'. Resources of the matching types are reported as non-compliant and all other resources as not applicable, so the policy never reports a resource as compliant.";

        /// <summary>
        /// The effects whose applicability is decided by the 'type' conditions only.
        /// </summary>
        private static readonly OrdinalInsensitiveHashSet TypeApplicabilityEffects = new OrdinalInsensitiveHashSet
        {
            "append",
            "audit",
            "deny",
            "modify",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="TypeOnlyIfCondition"/> class.
        /// </summary>
        public TypeOnlyIfCondition() : base(
            identifier: "type-only-if-condition",
            category: Category.BestPractices,
            title: TypeOnlyIfCondition.RuleTitle,
            descriptionFormat: TypeOnlyIfCondition.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyRule expression, LinterContext context)
        {
            if (context.IsControlPlanePolicyMode &&
                TypeOnlyIfCondition.HasTypeApplicabilityEffect(effect: expression.Then.Effect, context: context) &&
                TypeOnlyIfCondition.ChecksOnlyType(ifCondition: expression.If))
            {
                return new[]
                {
                    this.CreateInformational(expression.If),
                };
            }

            return Array.Empty<LinterOutput>();
        }

        /// <summary>
        /// Determines whether the effect is one whose applicability is decided by the 'type' conditions, or a parameter
        /// whose allowedValues are all such effects or 'disabled'.
        /// </summary>
        private static bool HasTypeApplicabilityEffect(Property effect, LinterContext context)
        {
            if (effect.HasLiteralValue)
            {
                return TypeOnlyIfCondition.TypeApplicabilityEffects.Contains(effect.Value.ToString());
            }

            return effect.HasSimpleParameterizedValue(context: context, out _, out var allowedValues, out _) &&
                allowedValues != null &&
                allowedValues.Any(value => TypeOnlyIfCondition.TypeApplicabilityEffects.Contains(value)) &&
                allowedValues.All(value => TypeOnlyIfCondition.TypeApplicabilityEffects.Contains(value) || value.EqualsOrdinalInsensitively("disabled"));
        }

        /// <summary>
        /// Determines whether every condition in the 'if' is a 'type' field condition.
        /// </summary>
        private static bool ChecksOnlyType(IfCondition ifCondition)
        {
            var checksOnlyType = true;
            ifCondition.Visit(new PolicyExpressionVisitor
            {
                Visit = node =>
                {
                    if (node is LeafCondition leaf && !"type".EqualsOrdinalInsensitively(leaf.Field?.FieldAccessorReference?.Identifier))
                    {
                        checksOnlyType = false;
                    }
                },
            });

            return checksOnlyType;
        }
    }
}
