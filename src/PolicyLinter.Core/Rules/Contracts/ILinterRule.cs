namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core
{
    /// <summary>
    /// The interface for a linter rule.
    /// </summary>
    public interface ILinterRule
    {
        /// <summary>
        /// The rule identifier.
        /// </summary>
        string Identifier { get; }

        /// <summary>
        /// The rule title.
        /// </summary>
        string Title { get; }

        /// <summary>
        /// The rule category.
        /// </summary>
        Category Category { get; }

        /// <summary>
        /// The rule description string format.
        /// </summary>
        string Description { get; }

        /// <summary>
        /// Whether the rule should also be applied to types that derive from the explicit type targeted by the linter rule.
        /// </summary>
        bool ApplyToDerivedTypes { get; }

        /// <summary>
        /// Evaluate the expression against the rule and return results as an array.
        /// </summary>
        /// <param name="expression">The expression.</param>
        /// <param name="context">Additional context for the rule evaluation.</param>
        LinterOutput[] Evaluate(PolicyExpressionBase expression, LinterContext context);
    }
}
