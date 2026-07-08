// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts
{
    /// <summary>
    /// The linter rule output category.
    /// </summary>
    public enum Category
    {
        /// <summary>
        /// The default category. Used when no category is specified.
        /// </summary>
        Unknown,

        /// <summary>
        /// Rules used for testing the linter.
        /// </summary>
        Test,

        /// <summary>
        /// Issues with a linter.
        /// </summary>
        Linter,

        /// <summary>
        /// Issues with a linter rule.
        /// </summary>
        LinterRule,

        /// <summary>
        /// Issues with policy parsing.
        /// </summary>
        Parsing,

        /// <summary>
        /// Issues with evaluated resource fields referenced by the policy definition.
        /// </summary>
        ResourceFields,

        /// <summary>
        /// Policy authoring best practices.
        /// </summary>
        BestPractices,

        /// <summary>
        /// Everything else.. TODO: figure out reasonable categories.
        /// </summary>
        Misc
    }
}
