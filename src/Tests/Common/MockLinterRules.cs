// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;

    /// <summary>
    /// A test linter rule for testing purposes.
    /// </summary>
    public class TestPolicyExpressionLinterRule : LinterRule<PolicyExpression>
    {
        public Func<TestPolicyExpressionLinterRule, PolicyExpression, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestPolicyExpressionLinterRule(string descriptionFormat = null) : base(
            identifier: "policy-expression-rule",
            category: Category.Test,
            title: "policy-expression-rule",
            descriptionFormat: descriptionFormat ?? "policy-expression-rule",
            applyToDerivedTypes: true)
        {
        }

        protected override LinterOutput[] Evaluate(PolicyExpression expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// A test linter rule for testing purposes.
    /// </summary>
    public class TestPolicyDefinitionLinterRule : LinterRule<PolicyDefinition>
    {
        public Func<TestPolicyDefinitionLinterRule, PolicyDefinition, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestPolicyDefinitionLinterRule(string descriptionFormat = null) : base(
            identifier: "test-policy-definition-rule",
            category: Category.Test,
            title: "Test rule 1",
            descriptionFormat: descriptionFormat ?? "Test rule 1 description",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(PolicyDefinition expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// A test linter rule for testing purposes.
    /// </summary>
    public class TestLeafConditionLinterRule : LinterRule<LeafCondition>
    {
        public Func<TestLeafConditionLinterRule, LeafCondition, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestLeafConditionLinterRule(string descriptionFormat = null) : base(
            identifier: "test-leaf-condition-rule",
            category: Category.Test,
            title: "Test rule",
            descriptionFormat: descriptionFormat ?? "Test rule description",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(LeafCondition expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// A test linter rule for quantifiers.
    /// </summary>
    public class TestQuantifierLinterRule : LinterRule<Quantifier>
    {
        public Func<TestQuantifierLinterRule, Quantifier, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestQuantifierLinterRule() : base(
            identifier: "test-quantifier-rule",
            category: Category.Test,
            title: "Test quantifier rule",
            descriptionFormat: "Test quantifier rule description",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(Quantifier expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Test linter rule targeting properties.
    /// </summary>
    public class TestPropertyLinterRule : LinterRule<Property>
    {
        public Func<TestPropertyLinterRule, Property, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestPropertyLinterRule() : base(
            identifier: "test-property-rule",
            category: Category.Test,
            title: "Test property rule",
            descriptionFormat: "Test property rule description",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(Property expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// A test linter rule for testing purposes.
    /// </summary>
    public class TestConditionLinterRule : LinterRule<Condition>
    {
        public Func<TestConditionLinterRule, Condition, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestConditionLinterRule() : base(
            identifier: "test-condition-rule",
            category: Category.Test,
            title: "Test rule",
            descriptionFormat: "Test rule description",
            applyToDerivedTypes: true)
        {
        }

        protected override LinterOutput[] Evaluate(Condition expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// A test linter rule for testing purposes.
    /// </summary>
    public class TestReferenceLinterRule : LinterRule<Reference>
    {
        public Func<TestReferenceLinterRule, Reference, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestReferenceLinterRule() : base(
            identifier: "test-reference-rule",
            category: Category.Test,
            title: "Test rule",
            descriptionFormat: "Test rule description",
            applyToDerivedTypes: true)
        {
        }

        protected override LinterOutput[] Evaluate(Reference expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// A test linter rule for testing purposes targeting Parameters
    /// </summary>
    public class TestParametersLinterRule : LinterRule<Parameter>
    {
        public Func<TestParametersLinterRule, Parameter, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestParametersLinterRule(string descriptionFormat = null) : base(
            identifier: "test-parameters-rule",
            category: Category.Test,
            title: "Test Parameters Rule",
            descriptionFormat: descriptionFormat ?? "Test rule for Parameters",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(Parameter expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// A test linter rule for testing purposes targeting ThenExpression.
    /// </summary>
    public class TestThenExpressionLinterRule : LinterRule<ThenExpression>
    {
        public Func<TestThenExpressionLinterRule, ThenExpression, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestThenExpressionLinterRule(string descriptionFormat = null) : base(
            identifier: "test-then-expression-rule",
            category: Category.Test,
            title: "Test ThenExpression Rule",
            descriptionFormat: descriptionFormat ?? "Test rule for ThenExpression",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }
    /// <summary>
    /// A test linter rule for testing purposes targeting TemplateLanguageExpression.
    /// </summary>
    public class TestTemplateLanguageExpressionLinterRule : LinterRule<TemplateLanguageExpression>
    {
        public Func<TestTemplateLanguageExpressionLinterRule, TemplateLanguageExpression, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestTemplateLanguageExpressionLinterRule(string descriptionFormat = null) : base(
            identifier: "test-template-language-expression-rule",
            category: Category.Test,
            title: "Test TemplateLanguageExpression Rule",
            descriptionFormat: descriptionFormat ?? "Test rule for TemplateLanguageExpression",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(TemplateLanguageExpression expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Test linter rule targeting count expressions.
    /// </summary>
    public class TestCountLinterRule : LinterRule<Count>
    {
        public Func<TestCountLinterRule, Count, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestCountLinterRule() : base(
            identifier: "test-count-rule",
            category: Category.Test,
            title: "Test count rule",
            descriptionFormat: "Test count rule description",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(Count expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Test linter rule targeting policy definition properties.
    /// </summary>
    public class TestPolicyDefinitionPropertiesLinterRule : LinterRule<PolicyDefinitionProperties>
    {
        public Func<TestPolicyDefinitionPropertiesLinterRule, PolicyDefinitionProperties, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestPolicyDefinitionPropertiesLinterRule() : base(
            identifier: "test-policy-definition-properties-rule",
            category: Category.Test,
            title: "Test Policy Definition Properties Rule",
            descriptionFormat: "Test rule for Policy Definition Properties",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(PolicyDefinitionProperties expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Test linter rule targeting external evaluation enforcement settings.
    /// </summary>
    public class TestExternalEvaluationEnforcementSettingsLinterRule : LinterRule<ExternalEvaluationEnforcementSettings>
    {
        public Func<TestExternalEvaluationEnforcementSettingsLinterRule, ExternalEvaluationEnforcementSettings, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestExternalEvaluationEnforcementSettingsLinterRule() : base(
            identifier: "test-external-evaluation-enforcement-settings-rule",
            category: Category.Test,
            title: "Test External Evaluation Enforcement Settings Rule",
            descriptionFormat: "Test rule for External Evaluation Enforcement Settings",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(ExternalEvaluationEnforcementSettings expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Test linter rule targeting endpoint settings.
    /// </summary>
    public class TestEndpointSettingsLinterRule : LinterRule<EndpointSettings>
    {
        public Func<TestEndpointSettingsLinterRule, EndpointSettings, LinterContext, IEnumerable<LinterOutput>> EvaluateFunc { get; set; }

        public TestEndpointSettingsLinterRule() : base(
            identifier: "test-endpoint-settings-rule",
            category: Category.Test,
            title: "Test Endpoint Settings Rule",
            descriptionFormat: "Test rule for Endpoint Settings",
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(EndpointSettings expression, LinterContext context)
        {
            if (this.EvaluateFunc != null)
            {
                return this.EvaluateFunc(this, expression, context).ToArray();
            }

            throw new NotImplementedException();
        }
    }
}
