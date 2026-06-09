// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions.EvaluationHelpers
{
    using System;
    using System.Linq;
    using global::Azure.Deployments.Core.Exceptions;
    using global::Azure.Deployments.Core.Extensions;
    using global::Azure.Deployments.Expression.Extensions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Abstract class representing a function result that can implement different ways of selecting a JToken property
    /// </summary>
    internal abstract class FunctionResult
    {
        /// <summary>
        /// Select a property from the current value
        /// </summary>
        /// <param name="property">Property to select</param>
        public abstract FunctionResult SelectProperty(JToken property);

        /// <summary>
        /// Get the current value as JToken
        /// </summary>
        public abstract JToken CurrentValue();
    }


    internal class JTokenSelectableFunctionResult : FunctionResult
    {
        /// <summary>
        /// The root JToken
        /// </summary>
        private readonly JToken root;

        /// <summary>
        /// Creates an instance of JTokenSelectableFunctionResult
        /// </summary>
        /// <param name="root">The root token</param>
        public JTokenSelectableFunctionResult(JToken root)
        {
            this.root = root;
        }

        /// <summary>
        /// Get the current value of the root token
        /// </summary>
        public override JToken CurrentValue()
        {
            return this.root;
        }

        /// <summary>
        /// Select a property from current root
        /// </summary>
        /// <param name="property">The property</param>
        public override FunctionResult SelectProperty(JToken property)
        {
            if (root == null || root.IsNullishJTokenType())
            {
                return new ErrorFunctionResult(errorMessage: $"Root token is null");
            }

            switch (this.root.Type)
            {
                case JTokenType.Array:
                    return SelectArrayProperty((root as JArray)!, property);
                case JTokenType.Object:
                    return SelectObjectProperty((root as JObject)!, property);
                default:
                    return new ErrorFunctionResult(errorMessage: $"Unexpected root token type: {this.root.Type}");
            }
        }

        /// <summary>
        /// Selects the array property from JSON object.
        /// </summary>
        /// <param name="root">The root node.</param>
        /// <param name="token">The child token.</param>
        private static FunctionResult SelectArrayProperty(JArray root, JToken token)
        {
            if (token.Type != JTokenType.Integer)
            {
                return new ErrorFunctionResult(errorMessage: $"Invalid array index: {token}");
            }

            var index = token.ToObject<int>();
            return index < 0 || index >= root.Count
                ? new ErrorFunctionResult(errorMessage: $"Array index out of bounds: {index}")
                : new JTokenSelectableFunctionResult(root: root[index]);
        }

        /// <summary>
        /// Selects the object property from JSON object.
        /// </summary>
        /// <param name="root">The root node.</param>
        /// <param name="token">The child token.</param>
        private static FunctionResult SelectObjectProperty(JObject root, JToken token)
        {
            if (!token.IsTextBasedJTokenType())
            {
                return new ErrorFunctionResult(errorMessage: $"Invalid property name: {token}");
            }

            var propertyName = token.ToObject<string>()!;
            if (!root.TryGetValue(propertyName, StringComparison.InvariantCultureIgnoreCase, out JToken? value))
            {
                var availableProperties = root
                    .Properties()
                    .Select(property => property.Name)
                    .ConcatStrings(", ");

                return new ErrorFunctionResult(errorMessage: $"Property '{propertyName}' does not exist. Available properties are: {availableProperties}");
            }

            return new JTokenSelectableFunctionResult(root: value);
        }
    }

    /// <summary>
    /// A function result that represents an error evaluating the function.
    /// </summary>
    /// <remarks>This allows for handling of errors without exceptions in some situations (mainly ShouldEvaluate), saving on throw/catch CPU cost.</remarks>
    internal class ErrorFunctionResult : FunctionResult
    {
        /// <summary>
        /// Gets the error message.
        /// </summary>
        public string ErrorMessage { get; }

        /// <summary>
        /// Creates an instance of <see cref="ErrorFunctionResult"/>
        /// </summary>
        /// <param name="errorMessage">The error message.</param>
        public ErrorFunctionResult(string errorMessage)
        {
            this.ErrorMessage = errorMessage;
        }

        /// <summary>
        /// Select a property from the current value
        /// </summary>
        /// <param name="property">Property to select</param>
        public override FunctionResult SelectProperty(JToken property)
        {
            throw new ExpressionException(message: this.ErrorMessage);
        }

        /// <summary>
        /// Get the current value as JToken
        /// </summary>
        public override JToken CurrentValue()
        {
            throw new ExpressionException(message: this.ErrorMessage);
        }
    }
}
