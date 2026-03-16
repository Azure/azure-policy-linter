namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter
{
    using System;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core;

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
