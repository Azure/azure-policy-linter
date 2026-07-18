namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System.Collections.Immutable;
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="OrderingOperatorOnIncompatibleFieldType"/> rule.
    /// </summary>
    public class OrderingOperatorOnIncompatibleFieldTypeTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        /// <summary>
        /// Returns one existing metadata entry with a fixed property type.
        /// </summary>
        private sealed class FixedTypeMetadata : ITypeMetadata
        {
            private readonly string type;

            /// <summary>
            /// Initializes a new instance of the <see cref="FixedTypeMetadata"/> class.
            /// </summary>
            /// <param name="type">The property type.</param>
            public FixedTypeMetadata(string type)
            {
                this.type = type;
            }

            /// <inheritdoc/>
            public bool TryGetAliasPropertyMetadata(string aliasName, out ResourcePropertyMetadata[] result)
            {
                result = new[]
                {
                    new ResourcePropertyMetadata
                    {
                        ResourceType = "Microsoft.Test/resources",
                        ApiVersions = ImmutableArray.Create("2025-01-01"),
                        Exists = true,
                        Type = this.type,
                    },
                };

                return true;
            }
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_BooleanField_ShouldFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Web/sites/httpsOnly"",
                        ""greater"": 5
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "ordering-operator-on-incompatible-field-type",
                Title: "Ordering Operator on Incompatible Field Type",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 8,
                LinePosition: 36,
                Path: "properties.policyRule.if.greater",
                Description: "The field alias 'Microsoft.Web/sites/httpsOnly' is of type 'boolean' in the latest API version and cannot be ordered with the 'greater' operator against a value of type 'number'. The comparison throws at evaluation, which fails the policy and implicitly denies the resource.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_ObjectField_ShouldFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Network/virtualNetworks/subnets[*]"",
                        ""lessOrEquals"": 3
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "ordering-operator-on-incompatible-field-type",
                Title: "Ordering Operator on Incompatible Field Type",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 8,
                LinePosition: 41,
                Path: "properties.policyRule.if.lessOrEquals",
                Description: "The field alias 'Microsoft.Network/virtualNetworks/subnets[*]' is of type 'object' in the latest API version and cannot be ordered with the 'lessOrEquals' operator against a value of type 'number'. The comparison throws at evaluation, which fails the policy and implicitly denies the resource.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_ArrayField_ShouldFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Storage/storageAccounts/networkAcls.ipRules"",
                        ""greater"": 1
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "ordering-operator-on-incompatible-field-type",
                Title: "Ordering Operator on Incompatible Field Type",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 8,
                LinePosition: 36,
                Path: "properties.policyRule.if.greater",
                Description: "The field alias 'Microsoft.Storage/storageAccounts/networkAcls.ipRules' is of type 'array' in the latest API version and cannot be ordered with the 'greater' operator against a value of type 'number'. The comparison throws at evaluation, which fails the policy and implicitly denies the resource.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_NumericFieldAgainstNonDateString_ShouldFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Compute/virtualMachines/storageProfile.dataDisks[*].diskSizeGB"",
                        ""less"": ""not-a-number""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "ordering-operator-on-incompatible-field-type",
                Title: "Ordering Operator on Incompatible Field Type",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 8,
                LinePosition: 46,
                Path: "properties.policyRule.if.less",
                Description: "The field alias 'Microsoft.Compute/virtualMachines/storageProfile.dataDisks[*].diskSizeGB' is of type 'number' in the latest API version and cannot be ordered with the 'less' operator against a value of type 'string'. The comparison throws at evaluation, which fails the policy and implicitly denies the resource.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_NumericFieldAgainstNumber_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Compute/virtualMachines/storageProfile.dataDisks[*].diskSizeGB"",
                        ""greater"": 128
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

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_NumericFieldAgainstDateString_ShouldFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Compute/virtualMachines/storageProfile.dataDisks[*].diskSizeGB"",
                        ""less"": ""2021-01-01T00:00:00Z""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "ordering-operator-on-incompatible-field-type",
                Title: "Ordering Operator on Incompatible Field Type",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 8,
                LinePosition: 54,
                Path: "properties.policyRule.if.less",
                Description: "The field alias 'Microsoft.Compute/virtualMachines/storageProfile.dataDisks[*].diskSizeGB' is of type 'number' in the latest API version and cannot be ordered with the 'less' operator against a value of type 'date'. The comparison throws at evaluation, which fails the policy and implicitly denies the resource.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_StringFieldAgainstNumber_ShouldFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Storage/storageAccounts/minimumTlsVersion"",
                        ""greater"": 5
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "ordering-operator-on-incompatible-field-type",
                Title: "Ordering Operator on Incompatible Field Type",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 8,
                LinePosition: 36,
                Path: "properties.policyRule.if.greater",
                Description: "The field alias 'Microsoft.Storage/storageAccounts/minimumTlsVersion' is of type 'string' in the latest API version and cannot be ordered with the 'greater' operator against a value of type 'number'. The comparison throws at evaluation, which fails the policy and implicitly denies the resource.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_StringFieldAgainstString_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Storage/storageAccounts/minimumTlsVersion"",
                        ""greater"": ""TLS1_1""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // A string field orders lexicographically against a string value; the types match.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_StringFieldAgainstDateString_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Storage/storageAccounts/minimumTlsVersion"",
                        ""greater"": ""2021-01-01T00:00:00Z""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // Dates are stored as strings, so a string field can hold a date and order against a date value.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_MixedStringAndNumericFieldAgainstString_ShouldFireForLatestNumericType()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Sql/servers/databases/maxSizeBytes"",
                        ""less"": ""not-a-number""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "ordering-operator-on-incompatible-field-type",
                Title: "Ordering Operator on Incompatible Field Type",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 8,
                LinePosition: 46,
                Path: "properties.policyRule.if.less",
                Description: "The field alias 'Microsoft.Sql/servers/databases/maxSizeBytes' is of type 'number' in the latest API version and cannot be ordered with the 'less' operator against a value of type 'string'. The comparison throws at evaluation, which fails the policy and implicitly denies the resource.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_MixedStringAndNumericFieldAgainstNumber_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Sql/servers/databases/maxSizeBytes"",
                        ""less"": 5
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // The alias is numeric in the latest API version, where the number value is orderable.
            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_NumericFieldAgainstBoolean_ShouldFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Compute/virtualMachines/storageProfile.dataDisks[*].diskSizeGB"",
                        ""greater"": true
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "ordering-operator-on-incompatible-field-type",
                Title: "Ordering Operator on Incompatible Field Type",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 8,
                LinePosition: 39,
                Path: "properties.policyRule.if.greater",
                Description: "The field alias 'Microsoft.Compute/virtualMachines/storageProfile.dataDisks[*].diskSizeGB' is of type 'number' in the latest API version and cannot be ordered with the 'greater' operator against a value of type 'boolean'. The comparison throws at evaluation, which fails the policy and implicitly denies the resource.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_NonOrderingOperator_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Web/sites/httpsOnly"",
                        ""equals"": true
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

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_ParameterizedValue_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""threshold"": {
                        ""type"": ""Integer""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Web/sites/httpsOnly"",
                        ""greater"": ""[parameters('threshold')]""
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

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_FieldMissingInLatestApiVersion_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.DocumentDB/databaseAccounts/ipRangeFilter"",
                        ""greater"": 5
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

        [Fact]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_UnresolvedAlias_ShouldNotFire()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Test/unknownResource/unknownProperty"",
                        ""greater"": 5
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

        [Theory]
        [InlineData("Any")]
        [InlineData("NotSpecified")]
        public void RuleTests_OrderingOperatorOnIncompatibleFieldType_UnknownMetadataType_ShouldNotFire(string fieldType)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OrderingOperatorOnIncompatibleFieldType()
                },
                metadata: new FixedTypeMetadata(type: fieldType));

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Test/resources/property"",
                        ""greater"": 5
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
