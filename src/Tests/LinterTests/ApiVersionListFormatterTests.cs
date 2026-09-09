// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Formatting;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="ApiVersionListFormatter"/>.
    /// </summary>
    public class ApiVersionListFormatterTests
    {
        /// <summary>
        /// Null input is rejected.
        /// </summary>
        [Fact]
        public void LinterTests_ApiVersionListFormatter_Format_NullVersions_Throws()
        {
            Action action = () => ApiVersionListFormatter.Format(apiVersions: null);

            action.Should().Throw<ArgumentNullException>();
        }

        /// <summary>
        /// An empty list produces an empty string.
        /// </summary>
        [Fact]
        public void LinterTests_ApiVersionListFormatter_Format_NoVersions_ReturnsEmptyString()
        {
            var result = ApiVersionListFormatter.Format(Array.Empty<string>());

            result.Should().BeEmpty();
        }

        /// <summary>
        /// One version is displayed unchanged.
        /// </summary>
        [Fact]
        public void LinterTests_ApiVersionListFormatter_Format_OneVersion_DisplaysVersion()
        {
            var result = ApiVersionListFormatter.Format(
                new[]
                {
                    "2025-01-01",
                });

            result.Should().Be("2025-01-01");
        }

        /// <summary>
        /// A stable version is displayed before its preview version.
        /// </summary>
        [Fact]
        public void LinterTests_ApiVersionListFormatter_Format_StableAndPreviewVersions_DisplaysStableFirst()
        {
            var result = ApiVersionListFormatter.Format(
                new[]
                {
                    "2025-01-01-preview",
                    "2025-01-01",
                });

            result.Should().Be("2025-01-01, 2025-01-01-preview");
        }

        /// <summary>
        /// One omitted version uses singular wording.
        /// </summary>
        [Fact]
        public void LinterTests_ApiVersionListFormatter_Format_OneOmittedVersion_UsesSingularWording()
        {
            var result = ApiVersionListFormatter.Format(
                new[]
                {
                    "2023-01-01",
                    "2024-01-01",
                    "2025-01-01",
                });

            result.Should().Be("2025-01-01, 2024-01-01, and 1 older API version");
        }

        /// <summary>
        /// Multiple omitted versions use plural wording.
        /// </summary>
        [Fact]
        public void LinterTests_ApiVersionListFormatter_Format_MultipleOmittedVersions_UsesPluralWording()
        {
            var result = ApiVersionListFormatter.Format(
                new[]
                {
                    "2022-01-01",
                    "2023-01-01",
                    "2024-01-01",
                    "2025-01-01",
                });

            result.Should().Be("2025-01-01, 2024-01-01, and 2 older API versions");
        }

        /// <summary>
        /// Duplicate versions are removed.
        /// </summary>
        [Fact]
        public void LinterTests_ApiVersionListFormatter_Format_DuplicateVersions_RemovesDuplicates()
        {
            var result = ApiVersionListFormatter.Format(
                new[]
                {
                    "2025-01-01-preview",
                    "2025-01-01-preview",
                    "2024-01-01",
                });

            result.Should().Be("2025-01-01-preview, 2024-01-01");
        }
    }
}
