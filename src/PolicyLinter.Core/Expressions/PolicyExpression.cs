// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System.Collections.Immutable;

    /// <summary>
    /// Dummy base class for policy expressions. Mainly used to allow the creation of <see cref="LinterRule{T}"/> where T is <see cref="PolicyExpression"/>.
    /// Without it, linter rules targeting <see cref="PolicyExpression"/> will trigger the following error: https://learn.microsoft.com/en-us/dotnet/csharp/misc/cs0462
    /// </summary>
    public abstract class PolicyExpressionBase
    {

    }

    /// <summary>
    /// An abstract policy expression to be evaluated by a linter rule.
    /// </summary>
    public abstract class PolicyExpression : PolicyExpressionBase
    {
        /// <summary>
        /// Gets or sets the line number of the expression withing the policy definition.
        /// </summary>
        public int? LineNumber { get; set; }

        /// <summary>
        /// Gets or sets the position number of the expression within the policy definition.
        /// </summary>
        public int? LinePosition { get; set; }

        /// <summary>
        /// The path of the expression.
        /// </summary>
        public string Path { get; }

        /// <summary>
        /// The path of the expression.
        /// </summary>
        /// <example>
        /// [ "if", "allOf[0]", "anyOf[1]", "not[0]" ]
        /// </example>
        public ImmutableArray<string> PathSegments { get; }

        /// <summary>
        /// The parent of this expressions.
        /// </summary>
        public PolicyExpression? Parent { get; }

        /// <summary>
        /// Visit the expression and its children with the given visitor.
        /// </summary>
        /// <param name="visitor">The visitor.</param>
        public abstract void Visit(PolicyExpressionVisitor visitor);

        /// <summary>
        /// Creates a new instance of the <see cref="PolicyExpression"/> class.
        /// </summary>
        /// <param name="lineNumber">The line number of the expression within the policy definition.</param>
        /// <param name="linePosition">The position number of the expression within the policy definition.</param>
        /// <param name="path">The expression path.</param>
        /// <param name="parent">The parent expression.</param>
        protected PolicyExpression(
            int? lineNumber,
            int? linePosition,
            ImmutableArray<string> path,
            PolicyExpression? parent)
        {
            this.LineNumber = lineNumber;
            this.LinePosition = linePosition;
            this.PathSegments = path;
            this.Path = string.Join(".", path);
            this.Parent = parent;
        }
    }
}
