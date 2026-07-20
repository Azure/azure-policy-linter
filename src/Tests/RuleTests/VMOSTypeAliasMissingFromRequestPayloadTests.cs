namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="VMOSTypeAliasMissingFromRequestPayload"/> rule.
    /// </summary>
    public class VMOSTypeAliasMissingFromRequestPayloadTests
    {
        private const string VMOSTypeAlias = "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType";
        private const string DescriptionFormat = "The field alias: '{0}' is absent from VM create/update payloads, so request-time {1} behavior does not occur for this condition. Existing-resource compliance can still evaluate it.";

        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("audit", "audit")]
        [InlineData("deny", "deny")]
        [InlineData("append", "append")]
        [InlineData("DeNy", "deny")]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_LiteralAffectedEffect(string effect, string expectedEffect)
        {
            var results = CreateLinter().Lint(LiteralEffectPolicy(effect: effect, fieldAlias: VMOSTypeAlias));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateOutput(
                lineNumber: 6,
                linePosition: 81,
                path: "properties.policyRule.if.field",
                alias: VMOSTypeAlias,
                effects: expectedEffect));
        }

        [Fact]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_AliasComparisonIsCaseInsensitive()
        {
            var alias = VMOSTypeAlias.ToUpperInvariant();
            var results = CreateLinter().Lint(LiteralEffectPolicy(effect: "audit", fieldAlias: alias));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateOutput(
                lineNumber: 6,
                linePosition: 81,
                path: "properties.policyRule.if.field",
                alias: alias,
                effects: "audit"));
        }

        [Fact]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_ParameterizedEffectWithOneAffectedAllowedValue()
        {
            var results = CreateLinter().Lint(ParameterizedEffectPolicy(
                parameterType: "String",
                allowedValuesProperty: @"""allowedValues"": [""disabled"", ""APPEND""]",
                effectExpression: "[parameters('effect')]"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateOutput(
                lineNumber: 13,
                linePosition: 81,
                path: "properties.policyRule.if.field",
                alias: VMOSTypeAlias,
                effects: "append"));
        }

        [Fact]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_ParameterizedEffectFormatsMultipleAffectedAllowedValuesInOrder()
        {
            var results = CreateLinter().Lint(ParameterizedEffectPolicy(
                parameterType: "String",
                allowedValuesProperty: @"""allowedValues"": [""append"", ""DENY"", ""audit""]",
                effectExpression: "[parameters('effect')]"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateOutput(
                lineNumber: 13,
                linePosition: 81,
                path: "properties.policyRule.if.field",
                alias: VMOSTypeAlias,
                effects: "audit, deny, or append"));
        }

        [Fact]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_UnconstrainedStringEffectParameter()
        {
            var results = CreateLinter().Lint(ParameterizedEffectPolicy(
                parameterType: "String",
                allowedValuesProperty: null,
                effectExpression: "[parameters('effect')]"));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateOutput(
                lineNumber: 12,
                linePosition: 81,
                path: "properties.policyRule.if.field",
                alias: VMOSTypeAlias,
                effects: "audit, deny, or append"));
        }

        [Fact]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_RootFieldFunctionValueReference()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""mode"": ""Indexed"",
    ""policyRule"": {
      ""if"": {
        ""value"": ""[field('Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType')]"",
        ""equals"": ""Windows""
      },
      ""then"": {
        ""effect"": ""deny""
      }
    }
  }
}";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateOutput(
                lineNumber: 6,
                linePosition: 92,
                path: "properties.policyRule.if.value",
                alias: VMOSTypeAlias,
                effects: "deny"));
        }

        [Fact]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_MultipleAliasReferences()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""mode"": ""Indexed"",
    ""policyRule"": {
      ""if"": {
        ""allOf"": [
          {
            ""field"": ""Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType"",
            ""equals"": ""Windows""
          },
          {
            ""value"": ""[field('Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType')]"",
            ""equals"": ""Windows""
          }
        ]
      },
      ""then"": {
        ""effect"": ""append""
      }
    }
  }
}";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(2);
            results.Should().ContainEquivalentOf(CreateOutput(
                lineNumber: 8,
                linePosition: 85,
                path: "properties.policyRule.if.allOf[0].field",
                alias: VMOSTypeAlias,
                effects: "append"));
            results.Should().ContainEquivalentOf(CreateOutput(
                lineNumber: 12,
                linePosition: 96,
                path: "properties.policyRule.if.allOf[1].value",
                alias: VMOSTypeAlias,
                effects: "append"));
        }

        [Theory]
        [InlineData("auditIfNotExists")]
        [InlineData("deployIfNotExists")]
        [InlineData("modify")]
        [InlineData("disabled")]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_UnaffectedLiteralEffect_NoFinding(string effect)
        {
            var results = CreateLinter().Lint(LiteralEffectPolicy(effect: effect, fieldAlias: VMOSTypeAlias));

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData(@"""allowedValues"": []")]
        [InlineData(@"""allowedValues"": [""disabled"", ""modify""]")]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_ParameterizedEffectWithoutAffectedAllowedValues_NoFinding(string allowedValuesProperty)
        {
            var results = CreateLinter().Lint(ParameterizedEffectPolicy(
                parameterType: "String",
                allowedValuesProperty: allowedValuesProperty,
                effectExpression: "[parameters('effect')]"));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_NonStringEffectParameter_NoFinding()
        {
            var results = CreateLinter().Lint(ParameterizedEffectPolicy(
                parameterType: "Array",
                allowedValuesProperty: @"""allowedValues"": [[""audit""], [""deny""]]",
                effectExpression: "[parameters('effect')]"));

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("[concat('de', 'ny')]")]
        [InlineData("[toLower(parameters('effect'))]")]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_ComplexEffectExpression_NoFinding(string effectExpression)
        {
            var results = CreateLinter().Lint(ParameterizedEffectPolicy(
                parameterType: "String",
                allowedValuesProperty: @"""allowedValues"": [""audit"", ""deny""]",
                effectExpression: effectExpression));

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("Microsoft.Compute/virtualMachines/storageProfile.osDisk.diskSizeGB")]
        [InlineData("Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.storageProfile.osDisk.osType")]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_OtherAlias_NoFinding(string fieldAlias)
        {
            var results = CreateLinter().Lint(LiteralEffectPolicy(effect: "deny", fieldAlias: fieldAlias));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_AliasOutsideIf_NoFinding()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""mode"": ""Indexed"",
    ""metadata"": {
      ""fieldReference"": ""[field('Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType')]""
    },
    ""policyRule"": {
      ""if"": {
        ""field"": ""type"",
        ""equals"": ""Microsoft.Compute/virtualMachines""
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_VMOSTypeAliasMissingFromRequestPayload_UnresolvedDynamicFieldReference_NoFinding()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""mode"": ""Indexed"",
    ""parameters"": {
      ""fieldName"": {
        ""type"": ""String"",
        ""defaultValue"": ""Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType""
      }
    },
    ""policyRule"": {
      ""if"": {
        ""field"": ""[parameters('fieldName')]"",
        ""equals"": ""Windows""
      },
      ""then"": {
        ""effect"": ""deny""
      }
    }
  }
}";

            var results = CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        private static PolicyLinter CreateLinter() => new PolicyLinter(
            rules: new ILinterRule[]
            {
                new VMOSTypeAliasMissingFromRequestPayload(),
            },
            metadata: MockMetadata);

        private static string LiteralEffectPolicy(string effect, string fieldAlias) => @"{
  ""properties"": {
    ""mode"": ""Indexed"",
    ""policyRule"": {
      ""if"": {
        ""field"": """ + fieldAlias + @""",
        ""equals"": ""Windows""
      },
      ""then"": {
        ""effect"": """ + effect + @"""
      }
    }
  }
}";

        private static string ParameterizedEffectPolicy(string parameterType, string allowedValuesProperty, string effectExpression)
        {
            var allowedValues = allowedValuesProperty == null ? string.Empty : $@"
        {allowedValuesProperty},";

            return @"{
  ""properties"": {
    ""mode"": ""Indexed"",
    ""parameters"": {
      ""effect"": {
        ""type"": """ + parameterType + @"""," + allowedValues + @"
        ""defaultValue"": ""disabled""
      }
    },
    ""policyRule"": {
      ""if"": {
        ""field"": ""Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType"",
        ""equals"": ""Windows""
      },
      ""then"": {
        ""effect"": """ + effectExpression + @"""
      }
    }
  }
}";
        }

        private static LinterOutput CreateOutput(int lineNumber, int linePosition, string path, string alias, string effects) => new LinterOutput(
            RuleIdentifier: "vm-os-type-alias-missing-from-request-payload",
            Title: "VM OS Type Alias Missing from Request Payload",
            Severity: Severity.Warning,
            Category: Category.ResourceFields,
            LineNumber: lineNumber,
            LinePosition: linePosition,
            Path: path,
            Description: string.Format(DescriptionFormat, alias, effects));
    }
}
