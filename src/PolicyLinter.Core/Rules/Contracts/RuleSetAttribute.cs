// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.Contracts
{
    using System;

    /// <summary>
    /// Attribute to specify a rule set name for a linter rule.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
    public sealed class RuleSetAttribute : Attribute
    {
        /// <summary>
        /// Gets the name of the rule set.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="RuleSetAttribute"/> class.
        /// </summary>
        /// <param name="name">The name of the rule set.</param>
        public RuleSetAttribute(string name)
        {
            Name = name;
        }
    }
}
