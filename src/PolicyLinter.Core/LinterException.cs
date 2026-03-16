namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core
{
    using System;

    /// <summary>
    /// An exception thrown by the linter when an unrecoverable error occurs.
    /// Contains a <see cref="LinterOutput"/> that describes the error and can be returned to the caller.
    /// </summary>
    public class LinterException : Exception
    {
        /// <summary>
        /// The result of the linter rule that caused the exception.
        /// </summary>
        public LinterOutput Result { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="LinterException"/> class with the specified result.
        /// </summary>
        public LinterException(LinterOutput result) : base(result.Description)
        {
            this.Result = result;
        }
    }
}
