namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="LengthFunctionOnArrayAlias"/> rule.
    /// </summary>
    public class LengthFunctionOnArrayAliasTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        /// <summary>
        /// Builds a policy definition with the given 'if' condition.
        /// </summary>
        private static string Policy(string condition) => @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": " + condition + @",
      ""then"": { ""effect"": ""audit"" }
    }
  }
}";

        private static LinterOutput[] Lint(string condition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new LengthFunctionOnArrayAlias() },
                metadata: LengthFunctionOnArrayAliasTests.MockMetadata);

            return linter.Lint(LengthFunctionOnArrayAliasTests.Policy(condition: condition));
        }

        [Theory]
        [InlineData("equals")]
        [InlineData("NotEquals")]
        [InlineData("greater")]
        [InlineData("greaterOrEquals")]
        [InlineData("less")]
        [InlineData("lessOrEquals")]
        public void RuleTests_LengthFunctionOnArrayAlias_NumericOperator(string conditionOperator)
        {
            var results = LengthFunctionOnArrayAliasTests.Lint(
                @"{ ""value"": ""[length(field('Microsoft.Test/resourceType/stringArray[*]'))]"", """ + conditionOperator + @""": 0 }");

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "length-function-on-array-alias",
                Title: "Length Function on Array Alias",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 4,
                LinePosition: 86,
                Path: "properties.policyRule.if.value",
                Description: "The condition checks the length of the array field 'Microsoft.Test/resourceType/stringArray[*]' using the length() function. Use a field count expression over 'Microsoft.Test/resourceType/stringArray[*]' instead."));
        }

        [Fact]
        public void RuleTests_LengthFunctionOnArrayAlias_CaseInsensitiveFunctionName()
        {
            var results = LengthFunctionOnArrayAliasTests.Lint(
                @"{ ""value"": ""[LENGTH(FIELD('Microsoft.Test/resourceType/stringArray[*]'))]"", ""greater"": 0 }");

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "length-function-on-array-alias",
                Title: "Length Function on Array Alias",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 4,
                LinePosition: 86,
                Path: "properties.policyRule.if.value",
                Description: "The condition checks the length of the array field 'Microsoft.Test/resourceType/stringArray[*]' using the length() function. Use a field count expression over 'Microsoft.Test/resourceType/stringArray[*]' instead."));
        }

        [Fact]
        public void RuleTests_LengthFunctionOnArrayAlias_InsideCountOverOtherArray()
        {
            var condition = @"{
        ""count"": {
          ""field"": ""Microsoft.Test/resourceType/objectArray[*]"",
          ""where"": { ""value"": ""[length(field('Microsoft.Test/resourceType/stringArray[*]'))]"", ""greater"": 0 }
        },
        ""greater"": 0
      }";

            LengthFunctionOnArrayAliasTests.Lint(condition).Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_LengthFunctionOnArrayAlias_FieldBoundToCountedArray()
        {
            var condition = @"{
        ""count"": {
          ""field"": ""Microsoft.Test/resourceType/stringArray[*]"",
          ""where"": { ""value"": ""[length(field('Microsoft.Test/resourceType/stringArray[*]'))]"", ""greater"": 3 }
        },
        ""greater"": 0
      }";

            LengthFunctionOnArrayAliasTests.Lint(condition).Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_LengthFunctionOnArrayAlias_CurrentFunction()
        {
            var condition = @"{
        ""count"": {
          ""field"": ""Microsoft.Test/resourceType/objectArray[*]"",
          ""where"": { ""value"": ""[length(current('Microsoft.Test/resourceType/objectArray[*].items[*]'))]"", ""greater"": 0 }
        },
        ""greater"": 0
      }";

            LengthFunctionOnArrayAliasTests.Lint(condition).Should().BeEmpty();
        }

        [Theory]
        [InlineData("[length(field('Microsoft.Test/resourceType/stringArray'))]")]
        [InlineData("[length(field('Microsoft.Test/resourceType/stringProperty'))]")]
        [InlineData("[length(field('Microsoft.Test/resourceType/objectArray[*].name'))]")]
        [InlineData("[length(parameters('values'))]")]
        [InlineData("[add(length(field('Microsoft.Test/resourceType/stringArray[*]')), 1)]")]
        [InlineData("[length(concat(field('Microsoft.Test/resourceType/stringArray[*]'), field('Microsoft.Test/resourceType/otherArray[*]')))]")]
        [InlineData("[length(first(field('Microsoft.Test/resourceType/stringArray[*]')))]")]
        [InlineData("[length(string(field('Microsoft.Test/resourceType/stringArray[*]')))]")]
        [InlineData("[length(field('Microsoft.Test/resourceType/stringArray[*]')[0])]")]
        public void RuleTests_LengthFunctionOnArrayAlias_NotLengthOfArrayAlias(string value)
        {
            var condition = @"{ ""value"": """ + value + @""", ""greater"": 0 }";

            LengthFunctionOnArrayAliasTests.Lint(condition).Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_LengthFunctionOnArrayAlias_NonNumericOperator()
        {
            var condition = @"{ ""value"": ""[length(field('Microsoft.Test/resourceType/stringArray[*]'))]"", ""in"": [ 1, 2 ] }";

            LengthFunctionOnArrayAliasTests.Lint(condition).Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_LengthFunctionOnArrayAlias_ValueIsNotASingleExpression()
        {
            var condition = @"{ ""value"": [ ""[length(field('Microsoft.Test/resourceType/stringArray[*]'))]"" ], ""greater"": 0 }";

            LengthFunctionOnArrayAliasTests.Lint(condition).Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_LengthFunctionOnArrayAlias_FieldCondition()
        {
            var condition = @"{ ""field"": ""Microsoft.Test/resourceType/stringProperty"", ""equals"": ""[length(field('Microsoft.Test/resourceType/stringArray[*]'))]"" }";

            LengthFunctionOnArrayAliasTests.Lint(condition).Should().BeEmpty();
        }
    }
}
