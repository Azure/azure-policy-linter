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

        [Fact]
        public void RuleTests_RiskyEffectParameterDefaultValue_ParameterizedEffectWithRiskyDefault()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                   new RiskyEffectParameterDefaultValue()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"  
               {  
                 ""properties"": {  
                   ""mode"": ""Indexed"",  
                   ""parameters"": {  
                     ""effect"": {  
                       ""type"": ""String"",  
                       ""defaultValue"": ""deny"",  
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 57,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the default value of the reference parameter: 'effect' is: 'deny'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to: 'audit' and: 'audit,deny,disabled' as the parameter allowed values."
            );

            results.Should().ContainEquivalentOf(output);

            // Now try to get fancy and have the parameter name as a static language expression. Should still work.
            linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                   new RiskyEffectParameterDefaultValue()
                },
                metadata: TypeMetadata);

            policyDefinition = policyDefinition.Replace("[parameters('effect')]", "[parameters(concat('e', 'ffect'))]");
            results = linter.Lint(policyDefinition);
            results.Should().HaveCount(1);

            output = new LinterOutput(
                RuleIdentifier: "risky-effect-parameter-default-value",
                Title: "Risky Effect Parameter Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 22,
                LinePosition: 69,
                Path: "properties.policyRule.then.effect",
                Description: "The policy effect is parameterized, but the default value of the reference parameter: 'effect' is: 'deny'. This increases the risk of accidentally assigning the policy with an enforcement effect. Consider setting the parameter default value to: 'audit' and: 'audit,deny,disabled' as the parameter allowed values."
            );

            results.Should().ContainEquivalentOf(output);
        }
    }
}
