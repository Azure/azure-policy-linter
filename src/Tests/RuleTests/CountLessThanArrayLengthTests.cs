namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="CountLessThanArrayLength"/> rule.
    /// </summary>
    public class CountLessThanArrayLengthTests
    {
        private const string Where = @"""where"": { ""field"": ""Microsoft.Test/resourceType/objectArray[*].state"", ""equals"": ""Allowed"" }";

        private static string Policy(string count, string operatorName, string value) => @"{
  ""properties"": {
    ""policyRule"": {
      ""if"": {
        ""count"": { " + count + @" },
        """ + operatorName + @""": " + value + @"
      },
      ""then"": { ""effect"": ""deny"" }
    }
  }
}";

        private static LinterOutput[] Lint(string policyDefinition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new CountLessThanArrayLength() },
                metadata: new MockTypeMetadata());

            return linter.Lint(policyDefinition);
        }

        [Theory]
        [InlineData("[length(field('Microsoft.Test/resourceType/objectArray[*]'))]")]
        [InlineData("[LENGTH(field('microsoft.test/resourceType/objectArray[*]'))]")]
        public void RuleTests_CountLessThanArrayLength_LessThanLength(string length)
        {
            var results = CountLessThanArrayLengthTests.Lint(CountLessThanArrayLengthTests.Policy(
                count: @"""field"": ""Microsoft.Test/resourceType/objectArray[*]"", " + CountLessThanArrayLengthTests.Where,
                operatorName: "less",
                value: @"""" + length + @""""));

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "count-less-than-array-length",
                Title: "Count Less Than Array Length",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: 79,
                Path: "properties.policyRule.if.less",
                Description: "The condition checks that the number of 'Microsoft.Test/resourceType/objectArray[*]' array members that match the 'where' condition is less than the array length. Count the array members that don't match instead, and check that the count is greater than 0."));
        }

        [Fact]
        public void RuleTests_CountLessThanArrayLength_NoWhere()
        {
            var results = CountLessThanArrayLengthTests.Lint(CountLessThanArrayLengthTests.Policy(
                count: @"""field"": ""Microsoft.Test/resourceType/objectArray[*]""",
                operatorName: "less",
                value: @"""[length(field('Microsoft.Test/resourceType/objectArray[*]'))]"""));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_CountLessThanArrayLength_OtherArray()
        {
            var results = CountLessThanArrayLengthTests.Lint(CountLessThanArrayLengthTests.Policy(
                count: @"""field"": ""Microsoft.Test/resourceType/objectArray[*]"", " + CountLessThanArrayLengthTests.Where,
                operatorName: "less",
                value: @"""[length(field('Microsoft.Test/resourceType/otherArray[*]'))]"""));

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("lessOrEquals", @"""[length(field('Microsoft.Test/resourceType/objectArray[*]'))]""")]
        [InlineData("less", "3")]
        [InlineData("less", @"""[add(length(field('Microsoft.Test/resourceType/objectArray[*]')), 1)]""")]
        public void RuleTests_CountLessThanArrayLength_OtherComparison(string operatorName, string value)
        {
            var results = CountLessThanArrayLengthTests.Lint(CountLessThanArrayLengthTests.Policy(
                count: @"""field"": ""Microsoft.Test/resourceType/objectArray[*]"", " + CountLessThanArrayLengthTests.Where,
                operatorName: operatorName,
                value: value));

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_CountLessThanArrayLength_ValueCount()
        {
            var results = CountLessThanArrayLengthTests.Lint(CountLessThanArrayLengthTests.Policy(
                count: @"""value"": ""[field('Microsoft.Test/resourceType/objectArray')]"", ""name"": ""item"", ""where"": { ""value"": ""[current('item').state]"", ""equals"": ""Allowed"" }",
                operatorName: "less",
                value: @"""[length(field('Microsoft.Test/resourceType/objectArray'))]"""));

            results.Should().BeEmpty();
        }
    }
}
