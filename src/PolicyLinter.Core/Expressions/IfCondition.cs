// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Represents the "if" condition of a policy rule.
    /// </summary>
    public class IfCondition : PolicyExpression
    {
        /// <summary>
        /// Resource types collected on first access and cached for this condition.
        /// </summary>
        private readonly Lazy<ImmutableHashSet<string>> referencedResourceTypes;

        /// <summary>
        /// The condition expression.
        /// </summary>
        public Condition Condition { get; }

        /// <summary>
        /// Gets the referenced resource types, using case-insensitive matching.
        /// </summary>
        /// <remarks>
        /// A best-effort, naive attempt to discover targeted resource types from references.
        /// It does not account for the actual policy rule logic.
        /// </remarks>
        public ImmutableHashSet<string> ReferencedResourceTypes => this.referencedResourceTypes.Value;

        /// <summary>
        /// Creates an instance of the <see cref="IfCondition"/> class.
        /// </summary>
        /// <param name="ifConditionProperty">The if condition expression.</param>
        /// <param name="parentPath">The path of the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public IfCondition(
            GenericObjectProperty<ConditionObject>? ifConditionProperty,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(ifConditionProperty?.LineNumber, ifConditionProperty?.LinePosition, parentPath.Concat("if").ToImmutableArray(), parent)
        {
            if (ifConditionProperty == null)
            {
                // TODO: Better exception
                throw new ArgumentNullException(nameof(ifConditionProperty), "If condition cannot be null.");
            }

            this.Condition = ifConditionProperty.CreateCondition(
                conditionPath: this.PathSegments,
                typeMetadata: typeMetadata,
                parent: this,
                countExpressionScopes: new Stack<CountExpressionScope>());

            this.referencedResourceTypes = new Lazy<ImmutableHashSet<string>>(valueFactory: this.ExtractReferencedResourceTypes);
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            if (visitor?.Visit != null)
            {
                visitor.Visit(this);
                this.Condition.Visit(visitor);
            }
        }

        private ImmutableHashSet<string> ExtractReferencedResourceTypes()
        {
            var resourceTypes = ImmutableHashSet.CreateBuilder<string>(equalityComparer: StringComparer.OrdinalIgnoreCase);
            this.Visit(visitor: new PolicyExpressionVisitor
            {
                Visit = node =>
                {
                    if (node is Reference reference && reference.IsResolvedFieldReference())
                    {
                        resourceTypes.UnionWith(other: reference.ResourcePropertyMetadata
                            .Select(selector: metadata => metadata.ResourceType)
                            .ToArray());
                    }
                    else if (node is LeafCondition leaf &&
                        string.Equals(a: leaf.Field?.FieldAccessorReference?.Identifier, b: "type", comparisonType: StringComparison.OrdinalIgnoreCase) &&
                        leaf.Operator != null)
                    {
                        resourceTypes.UnionWith(other: this.ExtractResourceTypes(leaf: leaf, leafOperator: leaf.Operator));
                    }
                }
            });
            return resourceTypes.ToImmutable();
        }

        private string[] ExtractResourceTypes(LeafCondition leaf, Property leafOperator)
        {
            var isEquals = leafOperator.Name.EqualsOrdinalInsensitively("equals");
            var isIn = leafOperator.Name.EqualsOrdinalInsensitively("in");
            var notCount = leaf.PathSegments.Count(predicate: segment => segment.EqualsOrdinalInsensitively("not"));
            if ((!isEquals && !isIn) || notCount % 2 != 0)
            {
                return Array.Empty<string>();
            }

            JToken? operand = leafOperator.Value;
            JToken?[]? values = null;
            if (!leafOperator.HasLiteralValue)
            {
                // PolicyRule's parent is the definition, not its properties object.
                var parameters = (this.Parent?.Parent as PolicyDefinition)?.Properties.Parameters;
                if (operand.Type != JTokenType.String ||
                    leafOperator.LanguageExpressions.Length != 1 ||
                    !leafOperator.LanguageExpressions[0].IsSimpleParameterReference(parameterName: out var parameterName) ||
                    parameters == null ||
                    !parameters.TryGetValue(key: parameterName, value: out var parameter) ||
                    !parameter.Type.EqualsOrdinalInsensitively(isEquals ? PolicyParameterType.String : PolicyParameterType.Array))
                {
                    return Array.Empty<string>();
                }

                values = parameter.AllowedValues;
                operand = parameter.DefaultValue;
            }
            else if (isIn && operand is not JArray)
            {
                return Array.Empty<string>();
            }

            if (values == null)
            {
                values = operand is JArray array ? array.ToArray() : new[] { operand };
            }

            var resourceTypes = new List<string>();
            foreach (var value in values)
            {
                if (value?.Type != JTokenType.String)
                {
                    continue;
                }

                var resourceType = value.ToString();
                var segments = resourceType.Split(separator: '/');
                if (segments.Length >= 2 && segments[0].Contains(value: '.', comparisonType: StringComparison.OrdinalIgnoreCase))
                {
                    resourceTypes.Add(item: resourceType);
                }
            }
            return resourceTypes.ToArray();
        }
    }
}
