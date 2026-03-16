namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core
{
    /// <summary>
    /// The severity of the rule output.
    /// </summary>
    public enum Severity
    {
        /// <summary>
        /// The default severity. This is used when the rule does not specify a severity.
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// Informational output. Suggestions, hints, etc.
        /// </summary>
        Informational,

        /// <summary>
        /// Warning output. Indicates a potential issue that should be reviewed.
        /// </summary>
        Warning,

        /// <summary>
        /// Error output. Indicates an issue that can block the creation of the policy or result in evaluation errors.
        /// </summary>
        Error,

        /// <summary>
        /// Critical error preventing the linter from continuing.
        /// </summary>
        Critical
    }
}
