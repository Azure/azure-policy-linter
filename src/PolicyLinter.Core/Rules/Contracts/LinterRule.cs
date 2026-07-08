// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts
{
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    /// <summary>
    /// The base linter rule class for evaluating a policy expression of type <typeparamref name="T"/>.
    /// </summary>
    /// <remarks>
    /// Implementations of this class should be thread-safe and stateless.
    /// </remarks>
    public abstract class LinterRule<T> : ILinterRule where T : PolicyExpressionBase
    {
        /// <inheritdoc />
        public string Identifier { get; }

        /// <inheritdoc />
        public string Title { get; }

        /// <inheritdoc />
        public Category Category { get; }

        /// <inheritdoc />
        public string Description { get; }

        /// <inheritdoc />
        public bool ApplyToDerivedTypes { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="LinterRule{T}"/> class with the specified identifier, title, category, and description.
        /// </summary>
        /// <param name="identifier">The rule identifier.</param>
        /// <param name="category">The rule category.</param>
        /// <param name="title">The rule title.</param>
        /// <param name="descriptionFormat">The rule description string format.</param>
        /// <param name="applyToDerivedTypes">Whether the rule should also be applied to types that derive from <typeparamref name="T"/>.</param>
        protected LinterRule(
            string identifier,
            Category category,
            string title,
            string descriptionFormat,
            bool applyToDerivedTypes)
        {
            this.Identifier = identifier;
            this.Category = category;
            this.Title = title;
            this.Description = descriptionFormat;
            this.ApplyToDerivedTypes = applyToDerivedTypes;
        }

        /// <inheritdoc />
        public LinterOutput[] Evaluate(PolicyExpressionBase expression, LinterContext context)
        {
            if (expression is null)
            {
                return new[] { BuiltinLinterOutputs.UnexpectedNullRuleInvocation(id: this.Identifier, title: this.Title) };
            }

            if (expression is not T typedExpression)
            {
                return new[] { BuiltinLinterOutputs.UnexpectedRuleInvocation(id: this.Identifier, title: this.Title, expectedExpressionType: typeof(T), actualExpressionType: expression.GetType()) };
            }

            return this.Evaluate(typedExpression, context);
        }

        /// <summary>
        /// Evaluate the expression against the rule.The implementation can call methods such as <see cref = "CreateError(PolicyExpression, object[])" /> to generate results for the rule.
        /// </summary>
        /// <param name="expression">The expression.</param>
        /// <param name="context">The context.</param>
        protected abstract LinterOutput[] Evaluate(T expression, LinterContext context);

        /// <summary>
        /// Create a linter error output for the current rule.
        /// </summary>
        /// <param name="expression">The evaluated expression.</param>
        /// <param name="descriptionParams">The description string format parameters.</param>
        public LinterOutput CreateError(PolicyExpression? expression, params object[] descriptionParams) => this.CreateOutput(expression, Severity.Error, descriptionParams);

        /// <summary>
        /// Create a linter warning output for the current rule.
        /// </summary>
        /// <param name="expression">The evaluated expression.</param>
        /// <param name="descriptionParams">The description string format parameters.</param>
        public LinterOutput CreateWarning(PolicyExpression? expression, params object[] descriptionParams) => this.CreateOutput(expression, Severity.Warning, descriptionParams);

        /// <summary>
        /// Create a linter informational output for the current rule.
        /// </summary>
        /// <param name="expression">The evaluated expression.</param>
        /// <param name="descriptionParams">The description string format parameters.</param>
        public LinterOutput CreateInformational(PolicyExpression? expression, params object[] descriptionParams) => this.CreateOutput(expression, Severity.Informational, descriptionParams);

        /// <summary>
        /// Create a linter output for the current rule.
        /// </summary>
        /// <param name="expression">The evaluated expression.</param>
        /// <param name="severity">The severity.</param>
        /// <param name="descriptionParams">The description string format parameters.</param>
        private LinterOutput CreateOutput(PolicyExpression? expression, Severity severity, params object[] descriptionParams)
        {
            return new LinterOutput(
                RuleIdentifier: this.Identifier,
                Title: this.Title,
                Severity: severity,
                Category: this.Category,
                LineNumber: expression?.LineNumber,
                LinePosition: expression?.LinePosition,
                Description: string.Format(this.Description, descriptionParams),
                Path: expression?.Path ?? string.Empty);
        }
    }
}
