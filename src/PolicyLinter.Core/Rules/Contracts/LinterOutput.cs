// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts
{
    /// <summary>
    /// Represents the output of a linter rule.
    /// </summary>
    /// <param name="RuleIdentifier">The rule Id.</param>
    /// <param name="Title">The rule title.</param>
    /// <param name="Category">The category.</param>
    /// <param name="Severity">The severity.</param>
    /// <param name="LineNumber">The line number in the policy definition where the issue was found.</param>
    /// <param name="LinePosition">The position in the line where the issue was found.</param>
    /// <param name="Description">The description</param>
    /// <param name="Path">The path to the location in the policy definition that the output is referring to.</param>
    public record LinterOutput(
        string RuleIdentifier,
        string Title,
        Category Category = Category.Unknown,
        Severity Severity = Severity.Unknown,
        int? LineNumber = null,
        int? LinePosition = null,
        string Description = "",
        string Path = "");
}
