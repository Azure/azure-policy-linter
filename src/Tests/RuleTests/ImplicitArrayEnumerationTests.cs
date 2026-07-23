namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="ImplicitArrayEnumeration"/> rule.
    /// </summary>
    public class ImplicitArrayEnumerationTests
    {
        private const string ArrayAlias = "Microsoft.Test/testResource/items[*].name";

        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_EqualsOutsideCount()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""field"": ""Microsoft.Test/testResource/items[*].name"",
        ""equals"": ""approved""
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertSingleFinding(
                policyDefinition: policyDefinition,
                lineNumber: 5,
                linePosition: 60,
                path: "properties.policyRule.if.field");
        }

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_ContainsOutsideCount()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""field"": ""Microsoft.Test/testResource/items[*].name"",
        ""contains"": ""prod""
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertSingleFinding(
                policyDefinition: policyDefinition,
                lineNumber: 5,
                linePosition: 60,
                path: "properties.policyRule.if.field");
        }

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_MixedPropertyAndOperatorCasing()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""FiElD"": ""Microsoft.Test/testResource/items[*].name"",
        ""EqUaLs"": ""approved""
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertSingleFinding(
                policyDefinition: policyDefinition,
                lineNumber: 5,
                linePosition: 60,
                path: "properties.policyRule.if.field");
        }

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_DifferentArrayInsideCountWhere()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""count"": {
          ""field"": ""Microsoft.Test/testResource/items[*]"",
          ""where"": {
            ""field"": ""Microsoft.Test/testResource/otherItems[*].name"",
            ""equals"": ""approved""
          }
        },
        ""greater"": 0
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertSingleFinding(
                policyDefinition: policyDefinition,
                lineNumber: 8,
                linePosition: 69,
                path: "properties.policyRule.if.count.where.field",
                alias: "Microsoft.Test/testResource/otherItems[*].name");
        }

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_NestedCountsOnlyMatchingScopesAreExempt()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""count"": {
          ""field"": ""Microsoft.Test/testResource/items[*]"",
          ""where"": {
            ""count"": {
              ""field"": ""Microsoft.Test/testResource/items[*].children[*]"",
              ""where"": {
                ""anyOf"": [
                  {
                    ""field"": ""Microsoft.Test/testResource/items[*].children[*].name"",
                    ""equals"": ""approved""
                  },
                  {
                    ""field"": ""Microsoft.Test/testResource/items[*].name"",
                    ""equals"": ""approved""
                  },
                  {
                    ""field"": ""Microsoft.Test/testResource/otherItems[*].name"",
                    ""equals"": ""approved""
                  }
                ]
              }
            },
            ""greater"": 0
          }
        },
        ""greater"": 0
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertSingleFinding(
                policyDefinition: policyDefinition,
                lineNumber: 21,
                linePosition: 77,
                path: "properties.policyRule.if.count.where.count.where.anyOf[2].field",
                alias: "Microsoft.Test/testResource/otherItems[*].name");
        }

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_MatchingFieldCountWhere()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""count"": {
          ""field"": ""Microsoft.Test/testResource/items[*]"",
          ""where"": {
            ""field"": ""Microsoft.Test/testResource/items[*].name"",
            ""equals"": ""approved""
          }
        },
        ""greater"": 0
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertNoFinding(policyDefinition);
        }

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_NestedArrayInsideOuterCountWhere()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""count"": {
          ""field"": ""Microsoft.Test/testResource/items[*]"",
          ""where"": {
            ""field"": ""Microsoft.Test/testResource/items[*].children[*].name"",
            ""equals"": ""approved""
          }
        },
        ""greater"": 0
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertSingleFinding(
                policyDefinition: policyDefinition,
                lineNumber: 8,
                linePosition: 76,
                path: "properties.policyRule.if.count.where.field",
                alias: "Microsoft.Test/testResource/items[*].children[*].name");
        }

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_ScalarAlias()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""field"": ""Microsoft.Test/testResource/name"",
        ""equals"": ""approved""
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertNoFinding(policyDefinition);
        }

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_ExistsOperator()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""field"": ""Microsoft.Test/testResource/items[*].name"",
        ""ExIsTs"": ""true""
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertNoFinding(policyDefinition);
        }

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_UnresolvedDynamicFieldAccessor()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""parameters"": {
      ""propertyName"": {
        ""type"": ""String""
      }
    },
    ""policyRule"": {
      ""if"": {
        ""field"": ""[concat('Microsoft.Test/testResource/items[*].', parameters('propertyName'))]"",
        ""equals"": ""approved""
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertNoFinding(policyDefinition);
        }

        [Fact]
        public void RuleTests_ImplicitArrayEnumeration_CurrentFunctionInValueCondition()
        {
            var policyDefinition = @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""count"": {
          ""field"": ""Microsoft.Test/testResource/items[*]"",
          ""where"": {
            ""value"": ""[current('Microsoft.Test/testResource/items[*]').name]"",
            ""equals"": ""approved""
          }
        },
        ""greater"": 0
      },
      ""then"": {
        ""effect"": ""audit""
      }
    }
  }
}";

            ImplicitArrayEnumerationTests.AssertNoFinding(policyDefinition);
        }

        private static void AssertSingleFinding(
            string policyDefinition,
            int lineNumber,
            int linePosition,
            string path,
            string alias = ImplicitArrayEnumerationTests.ArrayAlias)
        {
            var linter = ImplicitArrayEnumerationTests.CreateLinter();

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "implicit-array-enumeration",
                Title: "Implicit Array Enumeration",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: lineNumber,
                LinePosition: linePosition,
                Path: path,
                Description:
                    $"The field alias '{alias}' selects array members. Azure Policy applies the condition to every value selected by the array alias, and an empty collection satisfies it. Use field count when you need explicit member or empty-array handling.");

            results.Should().ContainEquivalentOf(output);
        }

        private static void AssertNoFinding(string policyDefinition)
        {
            var linter = ImplicitArrayEnumerationTests.CreateLinter();

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        private static PolicyLinter CreateLinter() => new PolicyLinter(
            rules: new ILinterRule[]
            {
                new ImplicitArrayEnumeration(),
            },
            metadata: ImplicitArrayEnumerationTests.MockMetadata);
    }
}
