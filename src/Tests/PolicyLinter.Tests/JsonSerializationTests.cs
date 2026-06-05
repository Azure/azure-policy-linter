// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Tests
{
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.Contracts;
    using System.Collections.Generic;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Parsing;
    using Newtonsoft.Json;
    using Xunit;

    /// <summary>
    /// Tests for JSON serialization of linter outputs, specifically enum handling.
    /// </summary>
    public class JsonSerializationTests
    {
        /// <summary>
        /// Tests that LinterOutput enums (Severity and Category) are serialized as string names instead of numeric values
        /// when using the linter's LinterOutputSerializerSettings.
        /// </summary>
        [Fact]
        public void JsonSerialization_LinterOutput_EnumsSerializedAsStrings()
        {
            // Arrange
            var linterOutput = new LinterOutput(
                RuleIdentifier: "test-rule",
                Title: "Test Rule",
                Category: Category.BestPractices,
                Severity: Severity.Warning,
                LineNumber: 42,
                LinePosition: 10,
                Description: "This is a test rule",
                Path: "properties.mode"
            );

            var results = new Dictionary<string, LinterOutput[]>
            {
                ["test-file.json"] = new[] { linterOutput }
            };

            // Act - Using the actual output settings that the CLI uses for serialization
            var json = JsonConvert.SerializeObject(results, LinterOutputSerializerSettings.Settings);

            // Assert
            Assert.True(json.Contains("\"severity\": \"Warning\""),
                $"Expected 'Warning' as string, but got: {json}");
            Assert.True(json.Contains("\"category\": \"BestPractices\""),
                $"Expected 'BestPractices' as string, but got: {json}");

            // Verify it doesn't contain numeric values
            Assert.False(json.Contains("\"severity\": 2"),
                $"Found numeric severity value in JSON: {json}");
            Assert.False(json.Contains("\"category\": 6"),
                $"Found numeric category value in JSON: {json}");
        }

        /// <summary>
        /// Tests that the serialized JSON can be deserialized back correctly when using LinterOutputSerializerSettings.
        /// </summary>
        [Fact]
        public void JsonSerialization_LinterOutput_RoundTripSerialization_WithStringEnums()
        {
            // Arrange
            var originalOutput = new LinterOutput(
                RuleIdentifier: "test-rule",
                Title: "Test Rule",
                Category: Category.ResourceFields,
                Severity: Severity.Error,
                LineNumber: 15,
                LinePosition: 5,
                Description: "This is a test rule",
                Path: "properties.policyRule.if.field"
            );

            var results = new Dictionary<string, LinterOutput[]>
            {
                ["test-policy.json"] = new[] { originalOutput }
            };

            // Act - Using the actual output settings that the CLI uses for serialization
            var json = JsonConvert.SerializeObject(results, LinterOutputSerializerSettings.Settings);
            var deserializedResults = JsonConvert.DeserializeObject<Dictionary<string, LinterOutput[]>>(json, LinterOutputSerializerSettings.Settings);

            // Assert
            Assert.NotNull(deserializedResults);
            Assert.True(deserializedResults.ContainsKey("test-policy.json"));

            var deserializedOutput = deserializedResults["test-policy.json"][0];
            Assert.Equal(originalOutput.RuleIdentifier, deserializedOutput.RuleIdentifier);
            Assert.Equal(originalOutput.Title, deserializedOutput.Title);
            Assert.Equal(originalOutput.Category, deserializedOutput.Category);
            Assert.Equal(originalOutput.Severity, deserializedOutput.Severity);
            Assert.Equal(originalOutput.LineNumber, deserializedOutput.LineNumber);
            Assert.Equal(originalOutput.LinePosition, deserializedOutput.LinePosition);
            Assert.Equal(originalOutput.Description, deserializedOutput.Description);
            Assert.Equal(originalOutput.Path, deserializedOutput.Path);
        }


    }
}
