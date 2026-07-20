// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Detects request-time effects whose conditions reference the VM OS type alias that is absent from create and update payloads.
    /// </summary>
    public sealed class VMOSTypeAliasMissingFromRequestPayload : LinterRule<PolicyDefinitionProperties>
    {
        private const string VMOSTypeAlias = "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType";
        private const string RuleTitle = "VM OS Type Alias Missing from Request Payload";
        private const string RuleDescription = "The field alias: '{0}' is absent from VM create/update payloads, so request-time {1} behavior does not occur for this condition. Existing-resource compliance can still evaluate it.";

        private static readonly string[] AffectedEffects =
        {
            "audit",
            "deny",
            "append",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="VMOSTypeAliasMissingFromRequestPayload"/> class.
        /// </summary>
        public VMOSTypeAliasMissingFromRequestPayload() : base(
            identifier: "vm-os-type-alias-missing-from-request-payload",
            category: Category.ResourceFields,
            title: VMOSTypeAliasMissingFromRequestPayload.RuleTitle,
            descriptionFormat: VMOSTypeAliasMissingFromRequestPayload.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyDefinitionProperties expression, LinterContext context)
        {
            var affectedEffects = VMOSTypeAliasMissingFromRequestPayload.GetAffectedEffects(
                effect: expression.PolicyRule.Then.Effect,
                context: context);
            if (affectedEffects.Length == 0)
            {
                return Array.Empty<LinterOutput>();
            }

            var affectedEffectsDescription = VMOSTypeAliasMissingFromRequestPayload.FormatEffects(affectedEffects);
            var outputs = new List<LinterOutput>();
            var visitor = new PolicyExpressionVisitor
            {
                Visit = (policyExpression) =>
                {
                    if (policyExpression is Reference reference &&
                        reference.IsResolvedFieldReference() &&
                        string.Equals(reference.Identifier, VMOSTypeAliasMissingFromRequestPayload.VMOSTypeAlias, StringComparison.OrdinalIgnoreCase))
                    {
                        outputs.Add(this.CreateWarning(reference, reference.Identifier, affectedEffectsDescription));
                    }
                },
            };

            expression.PolicyRule.If.Visit(visitor);

            return outputs.ToArray();
        }

        /// <summary>
        /// Gets the affected request-time effects that the policy can use.
        /// </summary>
        private static string[] GetAffectedEffects(Property effect, LinterContext context)
        {
            if (effect.HasLiteralValue)
            {
                var literalEffect = effect.Value.ToString();
                return VMOSTypeAliasMissingFromRequestPayload.AffectedEffects
                    .Where(affectedEffect => string.Equals(affectedEffect, literalEffect, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
            }

            if (!effect.HasSimpleParameterizedValue(context: context, out _, out var allowedValues, out _))
            {
                return Array.Empty<string>();
            }

            if (allowedValues == null)
            {
                return VMOSTypeAliasMissingFromRequestPayload.AffectedEffects;
            }

            return VMOSTypeAliasMissingFromRequestPayload.AffectedEffects
                .Where(affectedEffect => allowedValues.Any(allowedValue => string.Equals(allowedValue, affectedEffect, StringComparison.OrdinalIgnoreCase)))
                .ToArray();
        }

        /// <summary>
        /// Formats effect names in deterministic request-time evaluation order.
        /// </summary>
        private static string FormatEffects(string[] effects)
        {
            if (effects.Length == 1)
            {
                return effects[0];
            }

            if (effects.Length == 2)
            {
                return $"{effects[0]} or {effects[1]}";
            }

            return $"{string.Join(", ", effects.Take(effects.Length - 1))}, or {effects[^1]}";
        }
    }
}
