// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Flags a policy that blocks creation of role assignments or Privileged Identity
    /// Management activation requests: a 'deny' effect - literal, or a parameterized effect
    /// that can take a blocking value - whose 'if' targets the
    /// 'Microsoft.Authorization/roleAssignments' or
    /// 'Microsoft.Authorization/roleAssignmentScheduleRequests' type. Blocking their creation
    /// prevents granting or activating access under the scope the policy governs, which can
    /// lock administrators out with no way to reach a recovery role assignment.
    /// </summary>
    public sealed class BlockingEffectOnRoleAssignments : LinterRule<PolicyRule>
    {
        private const string RuleTitle = "Blocking Effect on Role Assignments";

        private const string RuleDescription =
            "The '{0}' effect blocks creation of role assignments or PIM activation requests ('Microsoft.Authorization/roleAssignments', 'Microsoft.Authorization/roleAssignmentScheduleRequests'), which prevents granting or activating access under the policy's scope and can lock administrators out. Ensure a standing recovery path at a parent scope that does not rely on creating a new role assignment.";

        private const string RoleAssignmentType = "Microsoft.Authorization/roleAssignments";

        private const string RoleAssignmentScheduleRequestType = "Microsoft.Authorization/roleAssignmentScheduleRequests";

        private const string DenyEffect = "deny";

        private static readonly OrdinalInsensitiveHashSet BlockingEffects = new OrdinalInsensitiveHashSet
        {
            BlockingEffectOnRoleAssignments.DenyEffect,
        };

        private static readonly string[] LockoutTypes = new[]
        {
            BlockingEffectOnRoleAssignments.RoleAssignmentType,
            BlockingEffectOnRoleAssignments.RoleAssignmentScheduleRequestType,
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="BlockingEffectOnRoleAssignments"/> class.
        /// </summary>
        public BlockingEffectOnRoleAssignments() : base(
            identifier: "blocking-effect-on-role-assignments",
            category: Category.BestPractices,
            title: BlockingEffectOnRoleAssignments.RuleTitle,
            descriptionFormat: BlockingEffectOnRoleAssignments.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(PolicyRule expression, LinterContext context)
        {
            var effect = expression.Then.Effect;

            var blockingEffect = BlockingEffectOnRoleAssignments.GetBlockingEffect(effect, context);
            if (blockingEffect == null)
            {
                return Array.Empty<LinterOutput>();
            }

            if (!BlockingEffectOnRoleAssignments.IfTargetsLockoutType(expression.If))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[]
            {
                this.CreateWarning(effect, blockingEffect),
            };
        }

        /// <summary>
        /// Determines whether the effect can take a blocking value, either as a literal or as
        /// one of the possible values of a parameterized effect.
        /// </summary>
        /// <param name="effect">The 'then' effect property.</param>
        /// <param name="context">The linter rule evaluation context.</param>
        /// <returns>The blocking effect value if one applies; otherwise null.</returns>
        private static string? GetBlockingEffect(Property effect, LinterContext context)
        {
            if (effect.HasLiteralValue)
            {
                var literal = effect.Value.ToStringValue();
                return literal != null && BlockingEffectOnRoleAssignments.BlockingEffects.Contains(literal) ? literal : null;
            }

            if (effect.HasSimpleParameterizedValue(context: context, out var _, out var allowedValues, out var _))
            {
                // Without an allowed-values allow-list the parameter is unconstrained, so a
                // blocking effect can be supplied at assignment time regardless of the default.
                if (allowedValues == null)
                {
                    return BlockingEffectOnRoleAssignments.DenyEffect;
                }

                return allowedValues.FirstOrDefault(value => BlockingEffectOnRoleAssignments.BlockingEffects.Contains(value));
            }

            return null;
        }

        /// <summary>
        /// Determines whether the 'if' condition contains a 'type' field condition that
        /// positively selects a lockout-prone type (role assignments or PIM activation requests).
        /// </summary>
        /// <param name="ifCondition">The policy rule's 'if' condition.</param>
        /// <returns>True if a 'type' condition targets a lockout type; otherwise false.</returns>
        private static bool IfTargetsLockoutType(IfCondition ifCondition)
        {
            var targetsLockoutType = false;

            var visitor = new PolicyExpressionVisitor
            {
                Visit = (expression) =>
                {
                    if (expression is LeafCondition leaf && BlockingEffectOnRoleAssignments.TargetsLockoutType(leaf))
                    {
                        targetsLockoutType = true;
                    }
                },
            };

            ifCondition.Visit(visitor);

            return targetsLockoutType;
        }

        /// <summary>
        /// Determines whether a leaf condition on the 'type' field selects a lockout-prone type
        /// via 'equals', 'in', or a wildcard 'like'. Both enclosing 'not' quantifiers and a
        /// negated operator ('notEquals', 'notIn', 'notLike') count as negations; an odd total
        /// number of them inverts the selection so the type is excluded rather than selected.
        /// </summary>
        /// <param name="leaf">The leaf condition to inspect.</param>
        /// <returns>True if the condition selects a lockout type; otherwise false.</returns>
        private static bool TargetsLockoutType(LeafCondition leaf)
        {
            var fieldName = leaf.Field?.FieldAccessorReference?.Identifier;
            if (!string.Equals(fieldName, "type", StringComparison.OrdinalIgnoreCase) ||
                leaf.Operator == null ||
                !leaf.Operator.HasLiteralValue)
            {
                return false;
            }

            if (!BlockingEffectOnRoleAssignments.TryGetTypeMatcher(leaf.Operator, out var matchesType, out var operatorNegated))
            {
                return false;
            }

            // Enclosing 'not' quantifiers and a negated operator both invert the condition; an
            // odd total number of negations means the type is excluded rather than selected.
            var negationCount =
                leaf.PathSegments.Count(segment => string.Equals(segment, "not", StringComparison.OrdinalIgnoreCase)) +
                (operatorNegated ? 1 : 0);

            return negationCount % 2 == 0 && matchesType;
        }

        /// <summary>
        /// Interprets a leaf condition's operator as a positive 'type' matcher paired with a flag
        /// indicating whether the operator itself is negated.
        /// </summary>
        /// <param name="op">The leaf condition's operator property.</param>
        /// <param name="matchesType">
        /// Whether the (positive form of the) operator's value matches a lockout type.
        /// </param>
        /// <param name="operatorNegated">Whether the operator is a negated form ('notEquals', 'notIn', 'notLike').</param>
        /// <returns>True if the operator is a recognized type matcher; otherwise false.</returns>
        private static bool TryGetTypeMatcher(Property op, out bool matchesType, out bool operatorNegated)
        {
            matchesType = false;
            operatorNegated = false;

            switch (op.Name?.ToLowerInvariant())
            {
                case "equals":
                    matchesType = BlockingEffectOnRoleAssignments.IsLockoutType(op.Value.ToStringValue());
                    return true;

                case "notequals":
                    operatorNegated = true;
                    matchesType = BlockingEffectOnRoleAssignments.IsLockoutType(op.Value.ToStringValue());
                    return true;

                case "like":
                    matchesType = BlockingEffectOnRoleAssignments.LikeMatchesLockoutType(op.Value.ToStringValue());
                    return true;

                case "notlike":
                    operatorNegated = true;
                    matchesType = BlockingEffectOnRoleAssignments.LikeMatchesLockoutType(op.Value.ToStringValue());
                    return true;

                case "in":
                    matchesType = BlockingEffectOnRoleAssignments.InSetMatchesLockoutType(op.Value);
                    return true;

                case "notin":
                    operatorNegated = true;
                    matchesType = BlockingEffectOnRoleAssignments.InSetMatchesLockoutType(op.Value);
                    return true;

                default:
                    return false;
            }
        }

        /// <summary>
        /// Checks whether an 'in'/'notIn' operand set contains a lockout type.
        /// </summary>
        private static bool InSetMatchesLockoutType(JToken value)
        {
            return value is JArray values &&
                values.Any(item => BlockingEffectOnRoleAssignments.IsLockoutType(item.ToStringValue()));
        }

        /// <summary>
        /// Checks whether a value is exactly one of the lockout types.
        /// </summary>
        private static bool IsLockoutType(string? value)
        {
            return BlockingEffectOnRoleAssignments.LockoutTypes.Any(
                type => string.Equals(value, type, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Checks whether a 'like' pattern matches one of the lockout types. The 'like' operator
        /// supports a single '*' wildcard; the text before it must prefix the type and the text
        /// after it must suffix the type.
        /// </summary>
        private static bool LikeMatchesLockoutType(string? pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                return false;
            }

            var wildcardIndex = pattern.IndexOf('*', StringComparison.Ordinal);
            if (wildcardIndex < 0)
            {
                return BlockingEffectOnRoleAssignments.IsLockoutType(pattern);
            }

            var prefix = pattern.Substring(0, wildcardIndex);
            var suffix = pattern.Substring(wildcardIndex + 1);

            return BlockingEffectOnRoleAssignments.LockoutTypes.Any(
                target => target.Length >= prefix.Length + suffix.Length &&
                    target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                    target.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));
        }
    }
}
