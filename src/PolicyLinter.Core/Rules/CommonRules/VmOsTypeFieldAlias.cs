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
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Flags policies that reference the VM OS type field alias, which the resource provider sets after the VM is created.
    /// </summary>
    public sealed class VmOsTypeFieldAlias : LinterRule<PolicyRule>
    {
        private const string RuleTitle = "VM OS Type Field Alias";

        private const string RuleDescription =
            "The field alias 'Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType' maps to a property that the resource provider sets after the VM is created. Conditions on it evaluate against a missing value when VMs are created. Identify the operating system from image properties such as 'Microsoft.Compute/imagePublisher'.";

        private const string OsTypeAlias = "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType";

        /// <summary>
        /// The effects that act on the create request.
        /// </summary>
        private static readonly OrdinalInsensitiveHashSet RequestEffects = new OrdinalInsensitiveHashSet
        {
            "append",
            "audit",
            "deny",
            "modify",
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="VmOsTypeFieldAlias"/> class.
        /// </summary>
        public VmOsTypeFieldAlias() : base(
            identifier: "vm-os-type-field-alias",
            category: Category.ResourceFields,
            title: VmOsTypeFieldAlias.RuleTitle,
            descriptionFormat: VmOsTypeFieldAlias.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyRule expression, LinterContext context)
        {
            if (!VmOsTypeFieldAlias.ActsOnRequests(effect: expression.Then.Effect, context: context))
            {
                return Array.Empty<LinterOutput>();
            }

            var outputs = new List<LinterOutput>();
            expression.If.Visit(new PolicyExpressionVisitor
            {
                Visit = node =>
                {
                    if (node is Reference reference &&
                        reference.IsResolvedFieldReference() &&
                        reference.Identifier.EqualsOrdinalInsensitively(VmOsTypeFieldAlias.OsTypeAlias))
                    {
                        outputs.Add(this.CreateWarning(reference));
                    }
                },
            });

            return outputs.ToArray();
        }

        /// <summary>
        /// Determines whether the effect acts on the create request, or is a parameter whose allowedValues include one that does.
        /// </summary>
        private static bool ActsOnRequests(Property effect, LinterContext context)
        {
            if (effect.HasLiteralValue)
            {
                return VmOsTypeFieldAlias.RequestEffects.Contains(effect.Value.ToString());
            }

            return effect.HasSimpleParameterizedValue(context: context, out _, out var allowedValues, out _) &&
                allowedValues != null &&
                allowedValues.Any(value => VmOsTypeFieldAlias.RequestEffects.Contains(value));
        }
    }
}
