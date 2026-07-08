// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using System.Threading.Tasks;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Cli;
    using Xunit;

    /// <summary>
    /// Tests for the Program class to verify file handling scenarios.
    /// </summary>
    public class ProgramFileHandlingTests : IDisposable
    {
        private readonly string[] tempFiles;
        private readonly string tempOutputFile;

        public ProgramFileHandlingTests()
        {
            // Create temporary files for testing
            tempFiles = new string[]
            {
                Path.GetTempFileName(),
                Path.GetTempFileName(),
                Path.GetTempFileName()
            };

            tempOutputFile = Path.GetTempFileName();
            File.Delete(tempOutputFile);
        }

        public void Dispose()
        {
            // Clean up temporary files
            foreach (var file in tempFiles)
            {
                if (File.Exists(file))
                {
                    File.Delete(file);
                }
            }

            if (File.Exists(tempOutputFile))
            {
                File.Delete(tempOutputFile);
            }
        }

        [Fact]
        public async Task Main_ValidPolicyFile_GeneratesOutput()
        {
            // Arrange - Create a valid policy file
            File.WriteAllText(tempFiles[0], GetValidPolicyJson());

            // Act
            using var console = new ConsoleOutputCapture();
            var (output, result) = await console.CaptureAsync(() =>
                Program.Main(new[] { tempFiles[0] }));

            // Assert
            result.Should().Be(0, "Program should return success code");
            output.Should().Contain("Done!", "Output should indicate completion");
            output.Should().NotContain("File Not Found", "Should not show file not found error");
            output.Should().NotContain("Failed to parse", "Should not show parsing error");
        }

        [Fact]
        public async Task Main_DuplicateInputFile_HandlesGracefully()
        {
            // Arrange - Create a valid policy file
            File.WriteAllText(tempFiles[0], GetValidPolicyJson());

            // Act - Pass the same file path twice
            using var console = new ConsoleOutputCapture();
            var (output, result) = await console.CaptureAsync(() =>
                Program.Main(new[] { tempFiles[0], tempFiles[0] }));

            // Assert
            result.Should().Be(0, "Program should return success code");
            output.Should().Contain("Duplicate file path detected", "Should warn about duplicate files");
            output.Should().Contain(tempFiles[0], "Should mention the duplicate file path");
        }

        [Fact]
        public async Task Main_NonExistingFile_ReportsFileNotFound()
        {
            // Arrange - Create a path to a non-existent file
            var nonExistentFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");

            // Act
            using var console = new ConsoleOutputCapture();
            var (output, result) = await console.CaptureAsync(() =>
                Program.Main(new[] { nonExistentFile }));

            // Assert
            result.Should().Be(0, "Program should return success code even for non-existent files");
            output.Should().Contain("File Not Found", "Should report file not found");
            output.Should().Contain(nonExistentFile, "Should mention the missing file path");
        }

        [Fact]
        public async Task Main_ExistingFileWithOutput_WritesToOutputFile()
        {
            // Arrange - Create a valid policy file
            File.WriteAllText(tempFiles[0], GetValidPolicyJson());

            // Act - Run with output file option
            using var console = new ConsoleOutputCapture();
            var (output, result) = await console.CaptureAsync(() =>
                Program.Main(new[] { tempFiles[0], "--output", tempOutputFile }));

            // Assert
            result.Should().Be(0, "Program should return success code");
            output.Should().Contain($"Results written to {tempOutputFile}", "Should indicate results were written to file");

            // Verify output file was created and contains valid JSON
            File.Exists(tempOutputFile).Should().BeTrue("Output file should be created");
            var fileContent = await File.ReadAllTextAsync(tempOutputFile);
            fileContent.Should().NotBeNullOrEmpty("Output file should not be empty");

            // Verify content is valid JSON with the expected structure
            Action parseAction = () => JsonDocument.Parse(fileContent);
            parseAction.Should().NotThrow("Output should be valid JSON");

            var jsonDoc = JsonDocument.Parse(fileContent);
            jsonDoc.RootElement.ValueKind.Should().Be(JsonValueKind.Object, "Output should be a JSON object");

            // Check for file path key (case-insensitive due to Windows drive letter differences)
            var hasFilePathKey = jsonDoc.RootElement.EnumerateObject()
                .Any(p => string.Equals(p.Name, tempFiles[0], StringComparison.OrdinalIgnoreCase));
            hasFilePathKey.Should().BeTrue("Output should contain the input file path as a key");
        }

        [Fact]
        public async Task Main_ArbitraryNonJsonFile_ReportsParsingError()
        {
            // Arrange - Create a non-JSON file
            var nonJsonContent = "This is not a JSON file content";
            File.WriteAllText(tempFiles[0], nonJsonContent);

            // Act
            using var console = new ConsoleOutputCapture();
            var (output, result) = await console.CaptureAsync(() =>
                Program.Main(new[] { tempFiles[0] }));

            // Assert
            result.Should().Be(0, "Program should return success code even for invalid files");
            output.Should().Contain("Failed to parse", "Should report parsing failure");
            output.Should().NotContain("File Not Found", "Should not report file not found");
        }

        [Fact]
        public async Task Main_EmptyFile_ReportsParsingError()
        {
            // Arrange - Create an empty file
            File.WriteAllText(tempFiles[0], string.Empty);

            // Act
            using var console = new ConsoleOutputCapture();
            var (output, result) = await console.CaptureAsync(() =>
                Program.Main(new[] { tempFiles[0] }));

            // Assert
            result.Should().Be(0, "Program should return success code even for empty files");
            output.Should().Contain("Failed to parse", "Should report parsing failure");
        }

        [Fact]
        public async Task Main_InvalidJsonFormat_ReportsParsingError()
        {
            // Arrange - Create file with invalid JSON (missing closing bracket)
            var invalidJson = @"{
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
                            ""effect"": ""audit""
                        }
                    }
                }"; // Missing closing bracket

            File.WriteAllText(tempFiles[0], invalidJson);

            // Act
            using var console = new ConsoleOutputCapture();
            var (output, result) = await console.CaptureAsync(() =>
                Program.Main(new[] { tempFiles[0] }));

            // Assert
            result.Should().Be(0, "Program should return success code even for invalid JSON");
            output.Should().Contain("Failed to parse", "Should report parsing failure");
        }

        [Fact]
        public async Task Main_MixOfValidAndInvalidFiles_ProcessesAll()
        {
            // Arrange
            // Valid policy file
            File.WriteAllText(tempFiles[0], GetValidPolicyJson());

            // Invalid JSON file
            File.WriteAllText(tempFiles[1], "Not a JSON file");

            // Non-existent file
            var nonExistentFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");

            // Act
            using var console = new ConsoleOutputCapture();
            var (output, result) = await console.CaptureAsync(() =>
                Program.Main(new[] { tempFiles[0], tempFiles[1], nonExistentFile, "--output", tempOutputFile }));

            // Assert
            result.Should().Be(0, "Program should return success code");
            output.Should().Contain($"Results written to {tempOutputFile}", "Should indicate results were written to file");

            // Verify output file contains entries for all files
            File.Exists(tempOutputFile).Should().BeTrue("Output file should be created");
            var fileContent = await File.ReadAllTextAsync(tempOutputFile);

            var jsonDoc = JsonDocument.Parse(fileContent);

            // Check for file path keys (case-insensitive due to Windows drive letter differences)
            bool HasFilePathKey(string path) => jsonDoc.RootElement.EnumerateObject()
                .Any(p => string.Equals(p.Name, path, StringComparison.OrdinalIgnoreCase));

            HasFilePathKey(tempFiles[0]).Should().BeTrue("Output should contain the valid file");
            HasFilePathKey(tempFiles[1]).Should().BeTrue("Output should contain the invalid file");
            HasFilePathKey(nonExistentFile).Should().BeTrue("Output should contain the non-existent file");
        }

        [Fact]
        public async Task Main_BinaryFile_HandlesGracefully()
        {
            // Arrange - Create a binary file
            using (var stream = File.OpenWrite(tempFiles[0]))
            {
                // Write some binary data
                var binaryData = new byte[] { 0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE };
                stream.Write(binaryData, 0, binaryData.Length);
            }

            // Act
            using var console = new ConsoleOutputCapture();
            var (output, result) = await console.CaptureAsync(() =>
                Program.Main(new[] { tempFiles[0] }));

            // Assert
            result.Should().Be(0, "Program should return success code even for binary files");
            // The exact error message might vary, but it should indicate a problem with parsing
            output.Should().Contain("Failed to parse", "Should report parsing failure");
        }

        private string GetValidPolicyJson()
        {
            // Using a parameterized effect to avoid the hardcoded effect rule
            return @"{
                ""properties"": {
                    ""displayName"": ""Test Policy"",
                    ""description"": ""A policy for testing"",
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                        ""effect"": {
                            ""type"": ""String"",
                            ""defaultValue"": ""audit"",
                            ""allowedValues"": [
                                ""audit"",
                                ""deny"",
                                ""disabled""
                            ]
                        }
                    },
                    ""policyRule"": {
                        ""if"": {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                        },
                        ""then"": {
                            ""effect"": ""[parameters('effect')]""
                        }
                    }
                }
            }";
        }
    }

    /// <summary>
    /// Helper class to capture console output during tests.
    /// </summary>
    public class ConsoleOutputCapture : IDisposable
    {
        private readonly StringWriter stringWriter;
        private readonly TextWriter originalOutput;
        private readonly StringBuilder capturedOutput;

        /// <summary>
        /// Initializes a new instance of the <see cref="ConsoleOutputCapture"/> class.
        /// </summary>
        public ConsoleOutputCapture()
        {
            capturedOutput = new StringBuilder();
            stringWriter = new StringWriter(capturedOutput);
            originalOutput = Console.Out;
            Console.SetOut(stringWriter);
        }

        /// <summary>
        /// Gets the captured console output.
        /// </summary>
        public string GetOutput()
        {
            stringWriter.Flush();
            return capturedOutput.ToString();
        }

        /// <summary>
        /// Executes the given action while capturing console output.
        /// </summary>
        /// <param name="action">The action to execute.</param>
        /// <returns>The captured output.</returns>
        public string Capture(Action action)
        {
            action();
            return GetOutput();
        }

        /// <summary>
        /// Executes the given async function while capturing console output.
        /// </summary>
        /// <typeparam name="T">The return type of the function.</typeparam>
        /// <param name="func">The async function to execute.</param>
        /// <returns>A tuple containing the captured output and the function result.</returns>
        public async Task<(string Output, T Result)> CaptureAsync<T>(Func<Task<T>> func)
        {
            var result = await func();
            return (GetOutput(), result);
        }

        /// <summary>
        /// Disposes resources used by the class.
        /// </summary>
        public void Dispose()
        {
            Console.SetOut(originalOutput);
            stringWriter.Dispose();
        }
    }
}