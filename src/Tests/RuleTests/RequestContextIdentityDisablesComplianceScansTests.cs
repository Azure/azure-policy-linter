namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="RequestContextIdentityDisablesComplianceScans"/> rule.
    /// </summary>
    public class RequestContextIdentityDisablesComplianceScansTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        private const string ExpectedDescription =
            "The policy rule uses the 'requestContext().identity' function. Compliance results show 'NotApplicable', while enforcement effects such as Deny, DeployIfNotExists, and Modify still run at request time.";

        [Fact]
        public void RuleTests_RequestContextIdentityDisablesComplianceScans_IdentityInValueExpression()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityDisablesComplianceScans()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Compute/virtualMachines""
                          },
                          {
                            ""value"": ""[tryGet(requestContext().identity, 'idtyp')]"",
                            ""equals"": ""user""
                          }
                        ]
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
                RuleIdentifier: "request-context-identity-disables-compliance-scans",
                Title: "Request Context Identity Disables Compliance Scans",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 83,
                Path: "properties.policyRule.if.allOf[1].value",
                Description: ExpectedDescription);

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RequestContextIdentityDisablesComplianceScans_IdentityWithNestedProperty()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityDisablesComplianceScans()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""p1"",
                        ""notIn"": ""[split(requestContext().identity.acrs, ',')]""
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
                RuleIdentifier: "request-context-identity-disables-compliance-scans",
                Title: "Request Context Identity Disables Compliance Scans",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 79,
                Path: "properties.policyRule.if.notIn",
                Description: ExpectedDescription);

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RequestContextIdentityDisablesComplianceScans_MultipleReferencesEmitSingleFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityDisablesComplianceScans()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""value"": ""[tryGet(requestContext().identity, 'idtyp')]"",
                            ""equals"": ""user""
                          },
                          {
                            ""value"": ""[tryGet(requestContext().identity, 'appid')]"",
                            ""notIn"": ""[parameters('allowedClientAppIds')]""
                          }
                        ]
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
                RuleIdentifier: "request-context-identity-disables-compliance-scans",
                Title: "Request Context Identity Disables Compliance Scans",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 83,
                Path: "properties.policyRule.if.allOf[0].value",
                Description: ExpectedDescription);

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RequestContextIdentityDisablesComplianceScans_IdentityAccessorIsCaseInsensitive()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityDisablesComplianceScans()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[requestContext().Identity.acrs]"",
                        ""exists"": ""true""
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
                RuleIdentifier: "request-context-identity-disables-compliance-scans",
                Title: "Request Context Identity Disables Compliance Scans",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 67,
                Path: "properties.policyRule.if.value",
                Description: ExpectedDescription);

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RequestContextIdentityDisablesComplianceScans_IdentityInThenDetails()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityDisablesComplianceScans()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Compute/virtualMachines""
                      },
                      ""then"": {
                        ""effect"": ""modify"",
                        ""details"": {
                          ""roleDefinitionIds"": [],
                          ""operations"": [
                            {
                              ""operation"": ""addOrReplace"",
                              ""field"": ""tags['environment']"",
                              ""value"": ""production"",
                              ""condition"": ""[equals(tryGet(requestContext().identity, 'idtyp'), 'user')]""
                            }
                          ]
                        }
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "request-context-identity-disables-compliance-scans",
                Title: "Request Context Identity Disables Compliance Scans",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: 36,
                Path: "properties.policyRule.then.details",
                Description: ExpectedDescription);

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RequestContextIdentityDisablesComplianceScans_RequestContextWithoutIdentity()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityDisablesComplianceScans()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[requestContext().apiVersion]"",
                        ""equals"": ""2021-09-01""
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
        public void RuleTests_RequestContextIdentityDisablesComplianceScans_NoRequestContext()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityDisablesComplianceScans()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Compute/virtualMachines""
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
