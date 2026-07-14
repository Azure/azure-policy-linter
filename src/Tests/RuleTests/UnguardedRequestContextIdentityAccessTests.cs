namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="UnguardedRequestContextIdentityAccess"/> rule.
    /// </summary>
    public class UnguardedRequestContextIdentityAccessTests
    {
        private static readonly ITypeMetadata TypeMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_UnguardedRequestContextIdentityAccess_DirectClaimAccess()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnguardedRequestContextIdentityAccess()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[requestContext().identity.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role']]"",
                        ""equals"": ""admin""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "unguarded-request-context-identity-access",
                Title: "Unguarded Request Context Identity Access",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 131,
                Path: "properties.policyRule.if.value",
                Description: "The 'requestContext().identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role' access selects a sub-property directly. If that path is absent from the auth token the expression fails at evaluation, which makes the policy an implicit deny. Use 'tryGet' to select it safely.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_UnguardedRequestContextIdentityAccess_DirectPropertyAccess_CaseInsensitiveIdentity()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnguardedRequestContextIdentityAccess()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[requestContext().Identity.userId]"",
                        ""equals"": ""x""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "unguarded-request-context-identity-access",
                Title: "Unguarded Request Context Identity Access",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 69,
                Path: "properties.policyRule.if.value",
                Description: "The 'requestContext().identity.userId' access selects a sub-property directly. If that path is absent from the auth token the expression fails at evaluation, which makes the policy an implicit deny. Use 'tryGet' to select it safely.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_UnguardedRequestContextIdentityAccess_TryGetGuardedAccess()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnguardedRequestContextIdentityAccess()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[coalesce(tryGet(requestContext().identity, 'claims', 'role'), '')]"",
                        ""equals"": ""admin""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedRequestContextIdentityAccess_IdentityItself()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnguardedRequestContextIdentityAccess()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[requestContext().identity]"",
                        ""exists"": ""true""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedRequestContextIdentityAccess_NonIdentityRequestContextProperty()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnguardedRequestContextIdentityAccess()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[requestContext().apiVersion.number]"",
                        ""equals"": ""x""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedRequestContextIdentityAccess_UnresolvedSelectionPath()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnguardedRequestContextIdentityAccess()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""parameters"": {
                      ""claimName"": {
                        ""type"": ""String""
                      }
                    },
                    ""mode"": ""All"",
                    ""policyRule"": {
                      ""if"": {
                        ""value"": ""[requestContext().identity.claims[parameters('claimName')]]"",
                        ""equals"": ""admin""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
