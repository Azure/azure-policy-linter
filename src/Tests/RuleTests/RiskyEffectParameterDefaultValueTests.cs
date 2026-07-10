namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="RiskyEffectParameterDefaultValue"/> rule.
    /// </summary>
    public class RiskyEffectParameterDefaultValueTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        /// <summary>
        /// Builds a policy definition whose effect is parameterized, with the given parameter default value.
        /// </summary>
        private static string ParameterizedEffectPolicy(string defaultValue) => @"  
           {  
             ""properties"": {  
               ""mode"": ""Indexed"",  
               ""parameters"": {  
                 ""effect"": {  
                   ""type"": ""String"",  
                   ""defaultValue"": """ + defaultValue + @""",  
                   ""allowedValues"": [  
                     ""audit"",  
                     ""deny"",  
                     ""disabled""  
                   ]  
                 }  
               },  
               ""policyRule"": {  
                 ""if"": {  
                   ""field"": ""type"",  
                   ""equals"": ""Microsoft.Storage/storageAccounts""  
                 },  
                 ""then"": {  
                   ""effect"": ""[parameters('effect')]""  
                 }  
               }  
             }  
           }";

        [Fact]
        public void RuleTests_RiskyEffectParameterDefaultValue_DefaultIsDeny()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new RiskyEffectParameterDefaultValue() },
                metadata: TypeMetadata);

            var results = linter.Lint(ParameterizedEffectPolicy(defaultValue: "deny"));

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 53,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the referenced parameter 'effect' defaults to an enforcement effect 'deny'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to 'audit'."
            );

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RiskyEffectParameterDefaultValue_DefaultIsDeployIfNotExists()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new RiskyEffectParameterDefaultValue() },
                metadata: TypeMetadata);

            var results = linter.Lint(ParameterizedEffectPolicy(defaultValue: "deployIfNotExists"));

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 53,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the referenced parameter 'effect' defaults to an enforcement effect 'deployIfNotExists'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to 'auditIfNotExists'."
            );

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RiskyEffectParameterDefaultValue_DefaultIsDenyAction()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new RiskyEffectParameterDefaultValue() },
                metadata: TypeMetadata);

            var results = linter.Lint(ParameterizedEffectPolicy(defaultValue: "denyAction"));

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 53,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the referenced parameter 'effect' defaults to an enforcement effect 'denyAction'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to 'auditAction'."
            );

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RiskyEffectParameterDefaultValue_DefaultIsCaseInsensitive()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new RiskyEffectParameterDefaultValue() },
                metadata: TypeMetadata);

            var results = linter.Lint(ParameterizedEffectPolicy(defaultValue: "Deny"));

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 53,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the referenced parameter 'effect' defaults to an enforcement effect 'Deny'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to 'audit'."
            );

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RiskyEffectParameterDefaultValue_StaticParameterNameExpression()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new RiskyEffectParameterDefaultValue() },
                metadata: TypeMetadata);

            var policyDefinition = ParameterizedEffectPolicy(defaultValue: "deny")
                .Replace("[parameters('effect')]", "[parameters(concat('e', 'ffect'))]");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 65,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the referenced parameter 'effect' defaults to an enforcement effect 'deny'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to 'audit'."
            );

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RiskyEffectParameterDefaultValue_SafeDefault()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new RiskyEffectParameterDefaultValue() },
                metadata: TypeMetadata);

            var results = linter.Lint(ParameterizedEffectPolicy(defaultValue: "audit"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_RiskyEffectParameterDefaultValue_ParameterizedEffectWithNoDefault()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new RiskyEffectParameterDefaultValue() },
                metadata: TypeMetadata);

            var policyDefinition = @"  
               {  
                 ""properties"": {  
                   ""mode"": ""Indexed"",  
                   ""parameters"": {  
                     ""effect"": {  
                       ""type"": ""String"",  
                       ""allowedValues"": [  
                         ""audit"",  
                         ""deny"",  
                         ""disabled""  
                       ]  
                     }  
                   },  
                   ""policyRule"": {  
                     ""if"": {  
                       ""field"": ""type"",  
                       ""equals"": ""Microsoft.Storage/storageAccounts""  
                     },  
                     ""then"": {  
                       ""effect"": ""[parameters('effect')]""  
                     }  
                   }  
                 }  
               }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_RiskyEffectParameterDefaultValue_HardCodedEffect()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new RiskyEffectParameterDefaultValue() },
                metadata: TypeMetadata);

            var policyDefinition = @"  
               {  
                 ""properties"": {  
                   ""mode"": ""Indexed"",  
                   ""policyRule"": {  
                     ""if"": {  
                       ""field"": ""type"",  
                       ""equals"": ""Microsoft.Storage/storageAccounts""  
                     },  
                     ""then"": {  
                       ""effect"": ""deny""  
                     }  
                   }  
                 }  
               }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
