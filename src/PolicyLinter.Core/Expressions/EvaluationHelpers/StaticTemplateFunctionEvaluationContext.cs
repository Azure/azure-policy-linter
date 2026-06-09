// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions.EvaluationHelpers
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
        /// Whether short-circuit evaluation is allowed.
        /// </summary>
        public bool IsShortCircuitAllowed => false;

        /// <summary>
        /// What is the current expression scope.
        /// </summary>
        public ExpressionScope Scope => ExpressionScope.Empty();

        private ExpressionBuiltInFunctions ExpressionBuiltInFunctions { get; } = new ExpressionBuiltInFunctions();

        public bool AllowInvalidProperty(Exception exception, FunctionExpression functionExpression, FunctionArgument[] functionParametersValues, JToken[] selectedProperties)
        {
            return false;
        }

        public JToken EvaluateFunction(FunctionExpression functionExpression, FunctionArgument[] parameters, IEvaluationContext context, global::Azure.Deployments.Core.ErrorResponses.TemplateErrorAdditionalInfo? additionalnfo)
        {
            return this.ExpressionBuiltInFunctions.EvaluateFunction(functionExpression.Function, parameters.SelectArray(p => p.Token!));
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
