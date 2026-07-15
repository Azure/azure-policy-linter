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
    /// Tests for the <see cref="EqualityCheckOnNumericField"/> rule.
    /// </summary>
    public class EqualityCheckOnNumericFieldTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Theory]
        // Integer property compared with 'equals'.
        [InlineData("Microsoft.KeyVault/vaults/softDeleteRetentionInDays", "equals", "\"5\"", 37)]
        // Integer property compared with 'notEquals'.
        [InlineData("Microsoft.KeyVault/vaults/softDeleteRetentionInDays", "notEquals", "\"5\"", 40)]
        // Property that is numeric in some API versions and a string in others.
        [InlineData("Microsoft.Sql/servers/databases/maxSizeBytes", "equals", "\"5\"", 37)]
        // Numeric JSON literal.
        [InlineData("Microsoft.KeyVault/vaults/softDeleteRetentionInDays", "eQuAls", "5", 37)]
        // Mixed-case 'notEquals' should also match case-insensitively.
        [InlineData("Microsoft.KeyVault/vaults/softDeleteRetentionInDays", "nOtEqUaLs", "\"5\"", 40)]
        public void RuleTests_EqualityCheckOnNumericField_NumericField_ShouldFire(string field, string @operator, string literalValue, int linePosition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EqualityCheckOnNumericField()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""__FIELD__"",
                        ""__OPERATOR__"": __VALUE__
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            policyDefinition = policyDefinition
                .Replace("__FIELD__", field)
                .Replace("__OPERATOR__", @operator)
                .Replace("__VALUE__", literalValue);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "equality-check-on-numeric-field",
                Title: "Equality Check on Numeric Field",
                Severity: Severity.Informational,
                Category: Category.ResourceFields,
                LineNumber: 8,
                LinePosition: linePosition,
                Description: $"The field alias: '{field}' maps to a numeric property, but the '{@operator}' condition compares it against a literal value. The operator coerces both operands to string, so numerically equal values whose string forms differ (for example '5.0' versus '5') can compare as unequal. Test the policy, or use a 'value' expression for type-accurate equality.",
                Path: "properties.policyRule.if." + @operator);

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        // A string-typed field alias: no string coercion concern.
        [InlineData("Microsoft.Storage/storageAccounts/sku.name", "equals")]
        // A boolean-typed field alias: booleans coerce deterministically, nothing to act on.
        [InlineData("Microsoft.Web/sites/httpsOnly", "equals")]
        // A numeric field but the operator is not an equality operator.
        [InlineData("Microsoft.KeyVault/vaults/softDeleteRetentionInDays", "greater")]
        // A plain top-level field that is not a field alias at all.
        [InlineData("location", "equals")]
        // An alias that does not resolve to any resource property metadata.
        [InlineData("Microsoft.Storage/storageAccounts/thisAliasDoesNotExist", "equals")]
        // A 'value' condition has no field reference for the rule to inspect.
        [InlineData(null, "equals")]
        public void RuleTests_EqualityCheckOnNumericField_NoFinding(string field, string @operator)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EqualityCheckOnNumericField()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        __FIELD_PROPERTY__
                        ""__OPERATOR__"": ""5""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            policyDefinition = policyDefinition
                .Replace(
                    "__FIELD_PROPERTY__",
                    field == null
                        ? @"""value"": ""[field('Microsoft.KeyVault/vaults/softDeleteRetentionInDays')]"","
                        : @"""field"": """ + field + @""",")
                .Replace("__OPERATOR__", @operator);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_EqualityCheckOnNumericField_ParameterizedValue_NoFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EqualityCheckOnNumericField()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""retention"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.KeyVault/vaults/softDeleteRetentionInDays"",
                        ""equals"": ""[parameters('retention')]""
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
