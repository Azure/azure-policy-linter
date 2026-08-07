// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System;
    using System.Linq;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Verifies that every rule shipped in this repository exposes a documentation URL that points at
    /// this repository's rule documentation.
    /// </summary>
    public class RuleDocumentationUrlTests
    {
        private const string ExpectedDocumentationUrlBase =
            "https://github.com/Azure/azure-policy-linter/blob/main/docs/Rules";

        [Fact]
        public void AllRules_DocumentationUrl_PointsToThisRepository()
        {
            // Discover every concrete rule the same way the CLI does: reflect over the Core assembly.
            var ruleTypes = typeof(ILinterRule).Assembly
                .GetTypes()
                .Where(type => !type.IsAbstract && !type.IsInterface && typeof(ILinterRule).IsAssignableFrom(type))
                .ToArray();

            ruleTypes.Should().NotBeEmpty("the Core assembly is expected to ship linter rules");

            foreach (var ruleType in ruleTypes)
            {
                var rule = (ILinterRule)Activator.CreateInstance(ruleType)!;

                rule.DocumentationUrl.Should().Be(
                    $"{ExpectedDocumentationUrlBase}/{rule.Identifier}.md",
                    $"rule '{ruleType.Name}' should link to its documentation page in this repository");
            }
        }
    }
}
