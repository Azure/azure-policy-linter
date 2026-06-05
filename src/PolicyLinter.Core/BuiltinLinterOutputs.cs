// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core
{
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.Contracts;
    using System;

    /// <summary>
    /// Collection of linter outputs returned by the linter itself and not from any provided rules.
    /// </summary>
    public static class BuiltinLinterOutputs
    {
        /// <summary>
        /// Creates a linter output indicating failure to parse the policy definition JSON.
        /// </summary>
        /// <param name="parserError">The error from the parser.</param>
        public static LinterOutput PolicyDefinitionParsingFailure(string parserError)
        {
            return new LinterOutput(
                RuleIdentifier: "system-rule",
                Title: "Policy Definition Parsing Failure",
                Severity: Severity.Critical,
                Category: Category.Parsing,
                Description: $"Failed to parse the provided policy definition JSON. Parsing error: {parserError}");
        }

        /// <summary>
        /// Notify the user that the input to the linter was a policy definition property bag instead of a full policy definition.
        /// </summary>
        public static LinterOutput DetectedPolicyDefinitionPropertyBagInput()
        {
            return new LinterOutput(
                RuleIdentifier: "system-rule",
                Title: "Linter Input Is Policy Definition Property Bag",
                Severity: Severity.Informational,
                Category: Category.Parsing,
                Description: $"The linter was provided the policy definition property bag instead of the expect full policy definition resource payload. The linter will wrap the property bag with a dummy policy definition resource and proceed with the evaluation.");
        }

        /// <summary>
        /// The linter invoked a linter rule with the wrong expression type.
        /// </summary>
        /// <param name="id">The rule Id.</param>
        /// <param name="title">The rule title.</param>
        /// <param name="expectedExpressionType">The expected expression type.</param>
        /// <param name="actualExpressionType">The actual expression type.</param>
        public static LinterOutput UnexpectedRuleInvocation(string id, string title, Type expectedExpressionType, Type actualExpressionType)
        {
            return new LinterOutput(
                RuleIdentifier: "system-rule",
                Title: "Invalid Linter Rule Invocation",
                Severity: Severity.Critical,
                Category: Category.Linter,
                Description: $"Linter rule: {id}, \"{title}\" is targeting '{expectedExpressionType.Name}' expressions but was invoked with '{actualExpressionType}'. This indicates a bug in the linter itself.");
        }

        /// <summary>
        /// The linter invoked a linter rule with the wrong expression type.
        /// </summary>
        /// <param name="id">The rule Id.</param>
        /// <param name="title">The rule title.</param>
        public static LinterOutput UnexpectedNullRuleInvocation(string id, string title)
        {
            return new LinterOutput(
                RuleIdentifier: "system-rule",
                Title: "Invalid Linter Rule Invocation",
                Severity: Severity.Critical,
                Category: Category.Linter,
                Description: $"Linter rule: {id}, \"{title}\" was invoked with a null expression. This indicates a bug in the linter itself.");
        }

        /// <summary>
        /// The linter doesn't currently support evaluating effect details.
        /// </summary>
        public static LinterOutput EffectDetailsNotSupported()
        {
            return new LinterOutput(
                RuleIdentifier: "system-rule",
                Title: "Effect Details Not Supported",
                Severity: Severity.Warning,
                Category: Category.Linter,
                Description: $"The linter doesn't currently support evaluating effect details");
        }

        /// <summary>
        /// Creates a linter output indicating that a file could not be found.
        /// </summary>
        /// <param name="filePath">The file path that was not found.</param>
        public static LinterOutput FileNotFound(string filePath)
        {
            return new LinterOutput(
                RuleIdentifier: "system-rule",
                Title: "File Not Found",
                Severity: Severity.Critical,
                Category: Category.Linter,
                Description: $"The specified file could not be found: {filePath}");
        }

        /// <summary>
        /// Creates a linter output indicating that a file could not be read.
        /// </summary>
        /// <param name="filePath">The file path that could not be read.</param>
        /// <param name="errorMessage">The error message from the exception.</param>
        public static LinterOutput FileReadError(string filePath, string errorMessage)
        {
            return new LinterOutput(
                RuleIdentifier: "system-rule",
                Title: "File Read Error",
                Severity: Severity.Critical,
                Category: Category.Linter,
                Description: $"Failed to read file '{filePath}': {errorMessage}");
        }
    }
}
