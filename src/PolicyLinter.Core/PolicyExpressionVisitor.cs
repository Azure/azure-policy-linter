// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using System;

    /// <summary>
    /// Visit the policy expression tree.
    /// </summary>
    public class PolicyExpressionVisitor
    {
        /// <summary>
        /// The action to be executed when visiting a policy expression.
        /// </summary>
        public Action<PolicyExpression>? Visit { get; set; }
    }
}
