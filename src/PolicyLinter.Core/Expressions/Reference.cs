// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using global::Azure.Deployments.Expression.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Extensions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Represents the details of an expression within the policy definition that refers to some external data.
    /// </summary>
    public class Reference : PolicyExpression
    {
        /// <summary>
        /// A static instance of an <see cref="IEvaluationContext"/> for builtin (i.e. static) functions only.
        /// </summary>
        private static readonly IEvaluationContext BuiltInFunctionsOnlyExpressionEvaluationContext = new StaticTemplateFunctionEvaluationContext();

        /// <summary>
        /// A dictionary that maps function names to their corresponding reference kinds.
        /// </summary>
        private static readonly ImmutableDictionary<string, ReferenceKind> FunctionNamesToReferenceKinds = new OrdinalInsensitiveDictionary<ReferenceKind>
        {
            ["field"] = ReferenceKind.ResourceField,
            ["parameters"] = ReferenceKind.PolicyParameterName,
            ["subscription"] = ReferenceKind.SubscriptionProperty,
            ["resourceGroup"] = ReferenceKind.ResourceGroupProperty,
            ["requestContext"] = ReferenceKind.RequestContextProperty,
            ["current"] = ReferenceKind.CurrentArrayMember,
            ["claims"] = ReferenceKind.PolicyTokenClaims
        }.ToImmutableDictionary();

        /// <summary>
        /// Gets or sets the kind of reference.
        /// </summary>
        public ReferenceKind Kind { get; }

        /// <summary>
        /// The reference identifier (e.g. policy parameter name). If the reference is not resolved, this will be empty.
        /// </summary>
        public string Identifier { get; }

        /// <summary>
        /// Represents the property path for language expressions with property selectors. e.g. parameters('x').y.z will have a property selection path of y.z.
        /// </summary>
        public PropertySelectionPath? PropertySelectionPath { get; }

        /// <summary>
        /// Whether the reference identifier (e.g. the policy parameter of field name) is known. If false, it probably means that the reference depends on another reference.
        /// </summary>
        public bool IsResolved { get; private set; }

        /// <summary>
        /// If the reference identifier is not resolved, this will contain the list of references that need to be resolved in order to resolve this reference.
        /// </summary>
        public ImmutableArray<Reference> ResolutionDependencies { get; }

        /// <summary>
        /// The count expression scope that is being referenced by field() or current() expressions in a 'count.where' condition.
        /// </summary>
        public CountExpressionScope? ReferencedCountExpressionScope { get; }

        /// <summary>
        /// The property metadata of any resource properties referenced by this reference.
        /// </summary>
        /// <remarks>
        /// If this array is empty, this isn't a field reference, or the field reference doesn't map to any metadata.
        /// In the case of aliases, this means that the alias doesn't exist at all. It DOES NOT mean that the alias is pointing to properties that don't exist. In that case, we will return metadata with Exists = false.
        /// </remarks>
        public ImmutableArray<ResourcePropertyMetadata> ResourcePropertyMetadata { get; }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);

            foreach (var dependency in this.ResolutionDependencies)
            {
                dependency.Visit(visitor);
            }

            if (this.PropertySelectionPath?.ResolutionDependencies != null)
            {
                foreach (var dependency in this.PropertySelectionPath.ResolutionDependencies)
                {
                    dependency.Visit(visitor);
                }
            }
        }

        /// <summary>
        /// Checks if this reference is a resolved field reference.
        /// </summary>
        /// <remarks>
        /// This method is needed because a field reference could also be expressed via current() functions, in which case the reference type will be <see cref="ReferenceKind.CurrentArrayMember"/>."/>.
        /// </remarks>
        public bool IsResolvedFieldReference() => this.IsResolved &&
                (this.Kind == ReferenceKind.ResourceField ||
                (this.Kind == ReferenceKind.CurrentArrayMember && this.ReferencedCountExpressionScope?.Type == CountScopeType.Field));


        /// <summary>
        /// Create a reference to a field which represents a field reference that is part of a field accessor expression.
        /// </summary>
        /// <param name="fieldAccessor">The field accessor value.</param>
        /// <param name="jTokenMetadata">The metadata of the JSON object from which this property was parsed.</param>
        /// <param name="fieldAccessorLanguageExpression">The language expression in the field accessor (if it is a language expression).</param>
        /// <param name="countExpressionScopes">Parent count expression scopes.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        /// <param name="path">The path to the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        public static Reference CreateFieldAccessorReference(
            string fieldAccessor,
            JTokenMetadata? jTokenMetadata,
            TemplateLanguageExpression? fieldAccessorLanguageExpression,
            Stack<CountExpressionScope> countExpressionScopes,
            ITypeMetadata typeMetadata,
            ImmutableArray<string> path,
            PolicyExpression parent)
        {
            return new Reference(
                fieldReferenceValue: fieldAccessor,
                resolutionDependencies: fieldAccessorLanguageExpression?.References ?? ImmutableArray<Reference>.Empty,
                countExpressionScopes: countExpressionScopes,
                typeMetadata: typeMetadata,
                jTokenMetadata: jTokenMetadata,
                path: path,
                parent: parent);
        }

        /// <summary>
        /// Extracts references from a language expression and adds them to the results list.
        /// </summary>
        /// <param name="languageExpression">The language expression.</param>
        /// <param name="jTokenMetadata">The metadata of the JSON object from which this property was parsed.</param>
        /// <param name="path">The path to the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="countExpressionScopes">The count expression scopes.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        /// <param name="results">The list to which the references will be added.</param>
        public static void FromLanguageExpression(
            LanguageExpression languageExpression,
            JTokenMetadata? jTokenMetadata,
            ImmutableArray<string> path,
            PolicyExpression parent,
            Stack<CountExpressionScope> countExpressionScopes,
            ITypeMetadata typeMetadata,
            List<Reference> results)
        {
            if (languageExpression is not FunctionExpression function)
            {
                return;
            }

            // TODO: Validate the number/type of arguments of known functions.

            // Note:
            // The parent of "child" references in the function's arguments/properties is the same as the parent of the current reference.
            // i.e. When extracting references from the policy condition: { "value": "[field(parameters('field'))]", "equals": "x" },
            // we resolve 2 references: "field" and "parameter" and both of them have the same parent (the "value" property).
            // We will also mark the parameter reference as a resolution dependency of the field reference, but we don't treat is as a **child** of the field.
            // There are 2 main reasons for this decision:
            // - If were to have this parent-child relationship, we would need to create the parent reference and pass it as the parent to the child references,
            // but on the other hand, the we want to keep the list of resolution dependencies on the parent, and we want this list to be immutable, this creates a circular dependency
            // We can work around it (and the original code did), but it makes the code more complex and less readable.
            // - Maintaining parent-child relationship makes it hard to deal with literal field references.
            // Consider the leaf condition: { "field": "[parameters('x')]", "equals": "y" }.
            // In this case, we want to create a reference that represents the **field property value**, and have the parameter reference as a resolution dependency.
            // But then if we have parent-child relationship, who would be the parent of the parameter reference?
            // Is it its "real" parent (the language expression in the property value) or the "field" reference we created?
            // It seems like it should be both, but we don't really want to have multiple parents.
            //
            // TODO: If there's a need for these "child" references to point back to the reference who depends on them,
            // we can add a "dependentReference" property to the reference class and set it to the reference that depends on it.
            var functionParamDependecies = new List<Reference>();
            foreach (var parameter in function.Parameters.CoalesceEnumerable())
            {
                Reference.FromLanguageExpression(
                    languageExpression: parameter,
                    jTokenMetadata: jTokenMetadata,
                    path: path,
                    parent: parent,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata,
                    results: functionParamDependecies);
            }

            var propertyDependecies = new List<Reference>();
            foreach (var property in function.Properties.CoalesceEnumerable())
            {
                Reference.FromLanguageExpression(
                    languageExpression: property,
                    jTokenMetadata: jTokenMetadata,
                    path: path,
                    parent: parent,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata,
                    results: propertyDependecies);
            }

            PropertySelectionPath? propertySelectionPath = null;
            if (function.Properties.CoalesceEnumerable().Any())
            {
                if (!propertyDependecies.Any())
                {
                    // No dependencies, so we can process the path.
                    var processedPath = function
                        .Properties
                        .Select(property => property.EvaluateExpression(BuiltInFunctionsOnlyExpressionEvaluationContext).ToStringValue()!)
                        .ToArray()!;

                    propertySelectionPath = new PropertySelectionPath(processedPath, isResolved: true, resolutionDependencies: null);
                }
                else
                {
                    // TODO: we can't easily reconstruct the property path from the parsed language expression so just use empty path for now.
                    // This might require making changes to the upstream package.
                    propertySelectionPath = new PropertySelectionPath(path: Array.Empty<string>(), isResolved: false, resolutionDependencies: propertyDependecies.ToArray());
                }
            }

            if (Reference.IsReferenceFunction(function, out var functionReferenceKind))
            {
                var reference = new Reference(
                    function: function,
                    kind: functionReferenceKind,
                    resolutionDependencies: functionParamDependecies.ToImmutableArray(),
                    propertySelectionPath: propertySelectionPath,
                    countExpressionScopes: countExpressionScopes,
                    typeMetadata: typeMetadata,
                    jTokenMetadata: jTokenMetadata,
                    path: path,
                    parent: parent);

                results.Add(reference);
            }
            else
            {
                // The function itself isn't a reference, so we just need to return any references we found in the parameters and properties.
                results.AddRange(functionParamDependecies);
                results.AddRange(propertyDependecies);
            }
        }

        /// <summary>
        /// Whether expression is a reference function. If so, returns the reference kind.
        /// </summary>
        /// <param name="expression">The language expression.</param>
        /// <param name="referenceKind">The reference kind (if it is a reference).</param>
        public static bool IsReferenceFunction(LanguageExpression expression, out ReferenceKind referenceKind)
        {
            if (expression is not FunctionExpression functionExpression)
            {
                referenceKind = ReferenceKind.Unknown;
                return false;
            }

            return Reference.FunctionNamesToReferenceKinds.TryGetValue(functionExpression.Function, out referenceKind);
        }

        private Reference(
            FunctionExpression function,
            ReferenceKind kind,
            ImmutableArray<Reference> resolutionDependencies,
            PropertySelectionPath? propertySelectionPath,
            Stack<CountExpressionScope> countExpressionScopes,
            ITypeMetadata typeMetadata,
            JTokenMetadata? jTokenMetadata,
            ImmutableArray<string> path,
            PolicyExpression parent) : base(jTokenMetadata?.LineNumber, jTokenMetadata?.LinePosition, path, parent)
        {
            this.Kind = kind;
            this.IsResolved = !resolutionDependencies.Any();
            this.ResolutionDependencies = resolutionDependencies;
            this.PropertySelectionPath = propertySelectionPath;

            if (this.Kind == ReferenceKind.PolicyParameterName || this.Kind == ReferenceKind.ResourceField)
            {
                // For parameter and field functions, we need to extract the first argument name to use as the identifier of the reference.
                this.Identifier = this.IsResolved && function.Parameters.Length > 0 ?
                    function.Parameters[0].EvaluateExpression(BuiltInFunctionsOnlyExpressionEvaluationContext).ToStringValue()!
                    : string.Empty;

                this.ReferencedCountExpressionScope =
                    this.IsResolved && this.Kind == ReferenceKind.ResourceField && FieldPathHelper.IsArrayAlias(this.Identifier) ?
                    countExpressionScopes.ResolveFieldFunctionReference(this.Identifier)
                    : null;
            }
            else if (this.Kind == ReferenceKind.PolicyTokenClaims)
            {
                // For claims function, extract the first argument if present (e.g., claims('aud'))
                // If no argument but has property selection path, use the property path as identifier (e.g., claims().iss -> "iss")
                if (this.IsResolved && function.Parameters.Length > 0)
                {
                    this.Identifier = function.Parameters[0].EvaluateExpression(BuiltInFunctionsOnlyExpressionEvaluationContext).ToStringValue()!;
                }
                else if (this.PropertySelectionPath?.IsResolved == true && this.PropertySelectionPath.Path.Length > 0)
                {
                    this.Identifier = string.Join(".", this.PropertySelectionPath.Path);
                }
                else
                {
                    this.Identifier = function.Function;
                }

                this.ReferencedCountExpressionScope = null;
            }
            else if (this.Kind == ReferenceKind.CurrentArrayMember)
            {
                this.Identifier = function.Parameters.Length > 0 ?
                    function.Parameters[0].EvaluateExpression(BuiltInFunctionsOnlyExpressionEvaluationContext).ToStringValue()!
                    : string.Empty;

                var countScopeIdentifier = string.IsNullOrEmpty(this.Identifier) ? null : this.Identifier;
                this.ReferencedCountExpressionScope = this.IsResolved ? countExpressionScopes.ResolveCurrentFunctionReference(countScopeIdentifier) : null;
            }
            else
            {
                // For stuff like resourceGroup function the identifier is just going to be the function name and the property selection path is more relevant.
                this.Identifier = function.Function;
                this.ReferencedCountExpressionScope = null;
            }

            // For resolved field references, we need to extract the metadata for the field.
            this.ResourcePropertyMetadata =
                this.IsResolvedFieldReference() && typeMetadata.TryGetAliasPropertyMetadata(this.Identifier, out var metadata) ?
                    metadata.ToImmutableArray()
                    : ImmutableArray<ResourcePropertyMetadata>.Empty;
        }

        /// <summary>
        /// Create a field reference from a literal field reference value.
        /// </summary>
        private Reference(
            string fieldReferenceValue,
            ImmutableArray<Reference> resolutionDependencies,
            Stack<CountExpressionScope> countExpressionScopes,
            ITypeMetadata typeMetadata,
            JTokenMetadata? jTokenMetadata,
            ImmutableArray<string> path,
            PolicyExpression parent) : base(jTokenMetadata?.LineNumber, jTokenMetadata?.LinePosition, path, parent)
        {
            this.Kind = ReferenceKind.ResourceField;
            this.IsResolved = !resolutionDependencies.Any();
            this.Identifier = this.IsResolved ? fieldReferenceValue : string.Empty;
            this.ResolutionDependencies = resolutionDependencies;
            this.PropertySelectionPath = null;
            this.ReferencedCountExpressionScope =
                this.IsResolved && this.Kind == ReferenceKind.ResourceField && FieldPathHelper.IsArrayAlias(this.Identifier) ?
                countExpressionScopes.ResolveFieldFunctionReference(this.Identifier)
                : null;

            this.ResourcePropertyMetadata =
                this.IsResolvedFieldReference() && typeMetadata.TryGetAliasPropertyMetadata(this.Identifier, out var metadata) ?
                    metadata.ToImmutableArray()
                    : ImmutableArray<ResourcePropertyMetadata>.Empty;
        }
    }

    /// <summary>
    /// Represents a property selection path expression. e.g. parameters('x').y.z will have a property selection path of y.z.
    /// </summary>
    public class PropertySelectionPath
    {
        /// <summary>
        /// Gets or sets the segments of the property path. e.g. ['a', 'b', 'c'] or [ '[parameters('x')]', 'b', 'c'] in cases where the property path is not resolved.
        /// </summary>
        public string[] Path { get; }

        /// <summary>
        /// Whether the property path is resolved
        /// </summary>
        public bool IsResolved { get; }

        /// <summary>
        /// If the property path is not resolved, this will contain the list of references that need to be resolved in order to resolve this path.
        /// </summary>
        public ImmutableArray<Reference> ResolutionDependencies { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="PropertySelectionPath"/> class.
        /// </summary>
        public PropertySelectionPath(
            string[] path,
            bool isResolved,
            Reference[]? resolutionDependencies)
        {
            this.Path = path;
            this.IsResolved = isResolved;
            this.ResolutionDependencies = resolutionDependencies.CoalesceEnumerable().ToImmutableArray();
        }
    }

    /// <summary>
    /// Specifies the kind of reference in a policy expression.
    /// </summary>
    public enum ReferenceKind
    {
        /// <summary>
        /// Unknown reference kind.
        /// </summary>
        Unknown,

        /// <summary>
        /// Reference to policy parameter name.
        /// </summary>
        PolicyParameterName,

        /// <summary>
        /// Reference to a field in the evaluated resource.
        /// </summary>
        ResourceField,

        /// <summary>
        /// Reference to a field in the subscription containing the evaluated resource.
        /// </summary>
        SubscriptionProperty,

        /// <summary>
        /// Reference to a field in the resource group containing the evaluated resource.
        /// </summary>
        ResourceGroupProperty,

        /// <summary>
        /// Reference to a request context field.
        /// </summary>
        RequestContextProperty,

        /// <summary>
        /// Reference expressed by a 'current()' function in a count expression.
        /// </summary>
        CurrentArrayMember,

        /// <summary>
        /// Reference to policy token claims accessed via the 'claims()' function.
        /// </summary>
        PolicyTokenClaims
    }
}
