namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="RequestContextIdentityIsEnforcementOnly"/> rule.
    /// </summary>
    public class RequestContextIdentityIsEnforcementOnlyTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        private const string ExpectedDescription =
            "The policy rule uses the 'requestContext().identity' function. Compliance scans produce no compliance data for the policy. The policy only performs enforcement actions based on its effect.";

        [Fact]
        public void RuleTests_RequestContextIdentityIsEnforcementOnly_IdentityInValueExpression()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityIsEnforcementOnly()
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
                RuleIdentifier: "request-context-identity-is-enforcement-only",
                Title: "Request Context Identity Is Enforcement Only",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 83,
                Path: "properties.policyRule.if.allOf[1].value",
                Description: ExpectedDescription);

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RequestContextIdentityIsEnforcementOnly_IdentityWithNestedProperty()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityIsEnforcementOnly()
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
                RuleIdentifier: "request-context-identity-is-enforcement-only",
                Title: "Request Context Identity Is Enforcement Only",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 8,
                LinePosition: 79,
                Path: "properties.policyRule.if.notIn",
                Description: ExpectedDescription);

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RequestContextIdentityIsEnforcementOnly_MultipleReferencesEmitSingleFinding()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityIsEnforcementOnly()
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
                RuleIdentifier: "request-context-identity-is-enforcement-only",
                Title: "Request Context Identity Is Enforcement Only",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 83,
                Path: "properties.policyRule.if.allOf[0].value",
                Description: ExpectedDescription);

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RequestContextIdentityIsEnforcementOnly_IdentityAccessorIsCaseInsensitive()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityIsEnforcementOnly()
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
                RuleIdentifier: "request-context-identity-is-enforcement-only",
                Title: "Request Context Identity Is Enforcement Only",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 67,
                Path: "properties.policyRule.if.value",
                Description: ExpectedDescription);

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_RequestContextIdentityIsEnforcementOnly_RequestContextWithoutIdentity()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityIsEnforcementOnly()
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
        public void RuleTests_RequestContextIdentityIsEnforcementOnly_NoRequestContext()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new RequestContextIdentityIsEnforcementOnly()
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
