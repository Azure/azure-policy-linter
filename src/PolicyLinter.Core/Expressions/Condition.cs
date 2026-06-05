// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions
{
    using System.Collections.Immutable;

    /// <summary>
    /// Represents a policy condition.
    /// </summary>
    public abstract class Condition : PolicyExpression
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Condition"/> class.
        /// </summary>
        /// <param name="lineNumber">The line number of the expression within the policy definition.</param>
        /// <param name="linePosition">The position number of the expression within the policy definition.</param>
        /// <param name="path">The expression path.</param>
        /// <param name="parent">The parent expressions.</param>
        protected Condition(
            int? lineNumber,
            int? linePosition,
            ImmutableArray<string> path,
            PolicyExpression parent) : base(lineNumber, linePosition, path, parent)
        {
        }
    }
}
