// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Detects a policy or initiative parameter that does not define a non-empty metadata.description.
    /// Without a description, whoever assigns the policy gets no guidance on the parameter's purpose or
    /// acceptable values.
    /// </summary>
    public sealed class ParameterMissingDescription : LinterRule<Parameter>
    {
        private const string RuleTitle = "Parameter Missing Description";
        private const string RuleDescription = "The parameter '{0}' has no 'metadata.description'. Without one, whoever assigns the policy gets no guidance on the parameter's purpose or acceptable values. Add a 'metadata.description'.";

        /// <summary>
        /// Initializes a new instance of the <see cref="ParameterMissingDescription"/> class.
        /// </summary>
        public ParameterMissingDescription() : base(
            identifier: "parameter-missing-description",
            category: Category.BestPractices,
            title: ParameterMissingDescription.RuleTitle,
            descriptionFormat: ParameterMissingDescription.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        /// <inheritdoc/>
        protected override LinterOutput[] Evaluate(Parameter expression, LinterContext context)
        {
            if (expression.Metadata is JObject metadata &&
                metadata.GetValue("description", StringComparison.OrdinalIgnoreCase) is JToken description &&
                description.Type == JTokenType.String &&
                !string.IsNullOrWhiteSpace(description.Value<string>()))
            {
                return Array.Empty<LinterOutput>();
            }

            return new[] { this.CreateInformational(expression: expression, expression.Name) };
        }
    }
}
