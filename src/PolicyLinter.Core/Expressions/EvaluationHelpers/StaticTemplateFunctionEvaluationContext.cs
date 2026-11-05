// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers
{
    using System;
    using global::Azure.Deployments.Expression.Expressions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Template function evaluation context for the policy linter.
    /// </summary>
    internal class StaticTemplateFunctionEvaluationContext : IEvaluationContext
    {
        /// <summary>
        /// Whether short-circuit evaluation is allowed. Policy evaluation evaluates only the selected branch of 'if()' and stops 'and()'/'or()' early, so this context does the same.
        /// </summary>
        public bool IsShortCircuitAllowed => true;

        /// <summary>
        /// What is the current expression scope.
        /// </summary>
        public ExpressionScope Scope => ExpressionScope.Empty();

        private static readonly ExpressionBuiltInFunctions BuiltInFunctions = new ExpressionBuiltInFunctions();

        private readonly string? parameterName;

        private readonly JToken? parameterValue;

        /// <summary>
        /// Creates a context that evaluates built-in functions only.
        /// </summary>
        public StaticTemplateFunctionEvaluationContext()
        {
        }

        /// <summary>
        /// Creates a context that evaluates built-in functions and resolves 'parameters()' for a single parameter to the given value.
        /// </summary>
        /// <param name="parameterName">The parameter name.</param>
        /// <param name="parameterValue">The parameter value.</param>
        public StaticTemplateFunctionEvaluationContext(string parameterName, JToken parameterValue)
        {
            this.parameterName = parameterName;
            this.parameterValue = parameterValue;
        }

        /// <summary>
        /// Whether the linter can evaluate the given built-in function.
        /// </summary>
        /// <param name="functionName">The function name.</param>
        public static bool IsBuiltInFunction(string functionName)
        {
            return StaticTemplateFunctionEvaluationContext.BuiltInFunctions.IsBuiltInFunction(functionName);
        }

        /// <summary>
        /// Evaluates a built-in function with the given argument values.
        /// </summary>
        /// <param name="functionName">The function name.</param>
        /// <param name="arguments">The argument values.</param>
        public static JToken EvaluateBuiltInFunction(string functionName, JToken[] arguments)
        {
            return StaticTemplateFunctionEvaluationContext.BuiltInFunctions.EvaluateFunction(functionName, arguments);
        }

        public bool AllowInvalidProperty(Exception exception, FunctionExpression functionExpression, FunctionArgument[] functionParametersValues, JToken[] selectedProperties)
        {
            return false;
        }

        public JToken EvaluateFunction(FunctionExpression functionExpression, FunctionArgument[] parameters, IEvaluationContext context, global::Azure.Deployments.Core.ErrorResponses.TemplateErrorAdditionalInfo? additionalnfo)
        {
            if (this.parameterName != null &&
                functionExpression.Function.EqualsOrdinalInsensitively("parameters") &&
                parameters.Length == 1 &&
                parameters[0].Token?.ToString().EqualsOrdinalInsensitively(this.parameterName) == true)
            {
                return this.parameterValue!.DeepClone();
            }

            return StaticTemplateFunctionEvaluationContext.BuiltInFunctions.EvaluateFunction(functionExpression.Function, parameters.SelectArray(p => p.Token!));
        }

        public bool ShouldIgnoreExceptionDuringEvaluation(Exception exception)
        {
            return false;
        }

        public IEvaluationContext WithNewScope(ExpressionScope scope)
        {
            throw new NotImplementedException();
        }
    }
}
