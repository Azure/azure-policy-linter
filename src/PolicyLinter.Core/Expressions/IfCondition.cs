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
        private readonly Lazy<ImmutableArray<string>> referencedResourceTypes;

        /// <summary>
        /// The condition expression.
        /// </summary>
        public Condition Condition { get; }

        /// <summary>
        /// Gets distinct resource types from resolved aliases and non-negated 'type' equals/in conditions.
        /// Simple parameter operands use allowed values, or their default when no allowed values are defined.
        /// </summary>
        /// <remarks>This is a list of references, not an evaluation of which resources the condition matches.</remarks>
        public ImmutableArray<string> ReferencedResourceTypes => this.referencedResourceTypes.Value;

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

            this.referencedResourceTypes = new Lazy<ImmutableArray<string>>(valueFactory: this.ExtractReferencedResourceTypes);
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

        private ImmutableArray<string> ExtractReferencedResourceTypes()
        {
            var resourceTypes = new HashSet<string>(comparer: StringComparer.OrdinalIgnoreCase);
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
            return resourceTypes.ToImmutableArray();
        }

        private IEnumerable<string> ExtractResourceTypes(LeafCondition leaf, Property leafOperator)
        {
            var isEquals = leafOperator.Name.EqualsOrdinalInsensitively("equals");
            var isIn = leafOperator.Name.EqualsOrdinalInsensitively("in");
            var notCount = leaf.PathSegments.Count(predicate: segment => segment.EqualsOrdinalInsensitively("not"));
            if ((!isEquals && !isIn) || notCount % 2 != 0)
            {
                yield break;
            }

            IEnumerable<JToken> values;
            if (leafOperator.HasLiteralValue)
            {
                if (isIn && leafOperator.Value is JArray array)
                {
                    values = array;
                }
                else if (isEquals && leafOperator.Value.Type == JTokenType.String)
                {
                    values = new[] { leafOperator.Value };
                }
                else
                {
                    yield break;
                }
            }
            else
            {
                // PolicyRule's parent is the definition, not its properties object.
                var parameters = (this.Parent?.Parent as PolicyDefinition)?.Properties.Parameters;
                if (leafOperator.Value.Type != JTokenType.String ||
                    leafOperator.LanguageExpressions.Length != 1 ||
                    !leafOperator.LanguageExpressions[0].IsSimpleParameterReference(parameterName: out var parameterName) ||
                    parameters == null ||
                    !parameters.TryGetValue(key: parameterName, value: out var parameter) ||
                    !parameter.Type.EqualsOrdinalInsensitively(isEquals ? PolicyParameterType.String : PolicyParameterType.Array))
                {
                    yield break;
                }

                if (parameter.AllowedValues != null)
                {
                    values = parameter.AllowedValues;
                }
                else if (parameter.DefaultValue is JArray defaultArray)
                {
                    values = defaultArray;
                }
                else if (parameter.DefaultValue != null)
                {
                    values = new[] { parameter.DefaultValue };
                }
                else
                {
                    yield break;
                }
            }

            foreach (var value in values)
            {
                if (value.Type != JTokenType.String)
                {
                    continue;
                }

                var resourceType = value.ToString();
                var segments = resourceType.Split(separator: '/');
                if (segments.Length >= 2 && segments[0].Contains(value: '.', comparisonType: StringComparison.OrdinalIgnoreCase))
                {
                    yield return resourceType;
                }
            }
        }
    }
}
