// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using System.IO;
    using System.Threading.Tasks;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Cli;
    using Xunit;

    /// <summary>
    /// Tests for the Program class to verify CLI console output formatting.
    /// </summary>
    [Collection("ConsoleOutput")]
    public class ProgramCliOutputTests : IDisposable
    {
        private readonly string tempFile;

        public ProgramCliOutputTests()
        {
            this.tempFile = Path.GetTempFileName();
        }

        public void Dispose()
        {
            if (File.Exists(this.tempFile))
            {
                File.Delete(this.tempFile);
            }
        }

        [Fact]
        public async Task Main_PolicyWithFinding_PrintsDocumentationLink()
        {
            // Arrange - Create a policy that triggers a rule (hard-coded enforcement effect)
            File.WriteAllText(this.tempFile, GetPolicyWithFindingJson());

            // Act
            using var console = new ConsoleOutputCapture();
            var (output, result) = await console.CaptureAsync(() =>
                Program.Main(new[] { this.tempFile }));

            // Assert
            result.Should().Be(0, "Program should return success code");
            output.Should().Contain(
                "Documentation: https://github.com/Azure/azure-policy-linter/blob/main/docs/Rules/",
                "Console output should include the documentation link for a finding");
        }

        private static string GetPolicyWithFindingJson()
        {
            // Hard-coded enforcement effect triggers a rule, guaranteeing at least one finding.
            return @"{
                ""properties"": {
                    ""displayName"": ""Test Policy"",
                    ""description"": ""A policy for testing"",
                    ""mode"": ""Indexed"",
                    ""parameters"": {},
                    ""policyRule"": {
                        ""if"": {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                        },
                        ""then"": {
                            ""effect"": ""deny""
                        }
                    }
                }
            }";
        }
    }
}
