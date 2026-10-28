namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="VmOsTypeFieldAlias"/> rule.
    /// </summary>
    public class VmOsTypeFieldAliasTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        private const string OsTypeCondition = @"{ ""field"": ""Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType"", ""equals"": ""Linux"" }";

        private static readonly LinterOutput ExpectedOutput = new LinterOutput(
            RuleIdentifier: "vm-os-type-field-alias",
            Title: "VM OS Type Field Alias",
            Severity: Severity.Warning,
            Category: Category.ResourceFields,
            LineNumber: 4,
            LinePosition: 87,
            Path: "properties.policyRule.if.field",
            Description: "The field alias 'Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType' maps to a property that the resource provider sets after the VM is created. Policies that depend on it don't act when VMs are created. Identify the operating system from image properties such as 'Microsoft.Compute/imagePublisher'.");

        private static string Policy(string condition, string effect = "deny", string parameters = "{}") => @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": " + condition + @",
      ""then"": { ""effect"": """ + effect + @""" }
    },
    ""parameters"": " + parameters + @"
  }
}";

        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new VmOsTypeFieldAlias() },
                metadata: VmOsTypeFieldAliasTests.TypeMetadata);

            return linter.Lint(policyDefinition);
        }

        [Theory]
        [InlineData("deny")]
        [InlineData("Audit")]
        [InlineData("append")]
        [InlineData("modify")]
        public void RuleTests_VmOsTypeFieldAlias_RequestEffect(string effect)
        {
            var results = VmOsTypeFieldAliasTests.Lint(VmOsTypeFieldAliasTests.Policy(condition: VmOsTypeFieldAliasTests.OsTypeCondition, effect: effect));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(VmOsTypeFieldAliasTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_VmOsTypeFieldAlias_WithImageCondition()
        {
            var condition = @"{ ""anyOf"": [ { ""field"": ""Microsoft.Compute/imagePublisher"", ""equals"": ""Canonical"" }, { ""field"": ""Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType"", ""equals"": ""Linux"" } ] }";

            var results = VmOsTypeFieldAliasTests.Lint(VmOsTypeFieldAliasTests.Policy(condition: condition));

            results.Should().HaveCount(1);
        }

        [Fact]
        public void RuleTests_VmOsTypeFieldAlias_ParameterAllowsRequestEffect()
        {
            var results = VmOsTypeFieldAliasTests.Lint(VmOsTypeFieldAliasTests.Policy(
                condition: VmOsTypeFieldAliasTests.OsTypeCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [ ""AuditIfNotExists"", ""Audit"" ] } }"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(VmOsTypeFieldAliasTests.ExpectedOutput);
        }

        [Fact]
        public void RuleTests_VmOsTypeFieldAlias_ParameterAllowsOnlyExistenceEffects()
        {
            var results = VmOsTypeFieldAliasTests.Lint(VmOsTypeFieldAliasTests.Policy(
                condition: VmOsTypeFieldAliasTests.OsTypeCondition,
                effect: "[parameters('effect')]",
                parameters: @"{ ""effect"": { ""type"": ""String"", ""allowedValues"": [ ""AuditIfNotExists"", ""Disabled"" ] } }"));

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("auditIfNotExists")]
        [InlineData("disabled")]
        public void RuleTests_VmOsTypeFieldAlias_OtherEffect(string effect)
        {
            var results = VmOsTypeFieldAliasTests.Lint(VmOsTypeFieldAliasTests.Policy(condition: VmOsTypeFieldAliasTests.OsTypeCondition, effect: effect));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_VmOsTypeFieldAlias_OtherAlias()
        {
            var condition = @"{ ""field"": ""Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.storageProfile.osDisk.osType"", ""equals"": ""Linux"" }";

            var results = VmOsTypeFieldAliasTests.Lint(VmOsTypeFieldAliasTests.Policy(condition: condition));

            results.Should().BeEmpty();
        }
    }
}
