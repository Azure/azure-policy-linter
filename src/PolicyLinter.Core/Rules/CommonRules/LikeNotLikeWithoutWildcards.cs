namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Rules
{
    using System;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core;

    /// <summary>
    /// Flags like/notLike conditions whose operand contains no wildcards (* or ?).
    /// Without wildcards these operators behave identically to equals/notEquals but
    /// are slower because the engine still performs pattern matching.
    /// </summary>
    public sealed class LikeNotLikeWithoutWildcards : LinterRule<LeafCondition>
    {
        private const string RuleTitle = "like/notLike Without Wildcards";
        private const string RuleDescription =
            "The condition uses the '{0}' operator with value '{1}' which contains no wildcards (* or ?). Use '{2}' for exact matching, which is more efficient and precise.";

        /// <summary>
        /// Initializes a new instance of the <see cref="LikeNotLikeWithoutWildcards"/> class.
        /// </summary>
        public LikeNotLikeWithoutWildcards() : base(
            identifier: "like-notlike-without-wildcards",
            category: Category.BestPractices,
            title: LikeNotLikeWithoutWildcards.RuleTitle,
            descriptionFormat: LikeNotLikeWithoutWildcards.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            if (expression.Operator == null)
            {
                return Array.Empty<LinterOutput>();
            }

            var operatorName = expression.Operator.Name;

            if (!string.Equals(operatorName, "like", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(operatorName, "notLike", StringComparison.OrdinalIgnoreCase))
            {
                return Array.Empty<LinterOutput>();
            }

            if (!expression.Operator.HasLiteralValue)
            {
                return Array.Empty<LinterOutput>();
            }

            var operandValue = expression.Operator.Value.ToString();

            if (operandValue.Contains('*', StringComparison.Ordinal) || operandValue.Contains('?', StringComparison.Ordinal))
            {
                return Array.Empty<LinterOutput>();
            }

            var replacement = string.Equals(operatorName, "like", StringComparison.OrdinalIgnoreCase)
                ? "equals"
                : "notEquals";

            return new[]
            {
                this.CreateWarning(expression.Operator, operatorName, operandValue, replacement)
            };
        }
    }
}
