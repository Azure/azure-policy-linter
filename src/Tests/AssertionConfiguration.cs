// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System.Runtime.CompilerServices;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;

    /// <summary>
    /// Assembly-wide FluentAssertions configuration.
    /// </summary>
    internal static class AssertionConfiguration
    {
        /// <summary>
        /// Excludes <see cref="LinterOutput.DocumentationUrl"/> from equivalence comparisons. Rule tests assert
        /// rule behavior via full-output equivalence; the documentation URL is deterministically derived from the
        /// rule identifier and is covered by a dedicated test, so it is not re-asserted per rule.
        /// </summary>
        [ModuleInitializer]
        internal static void Configure()
        {
            AssertionOptions.AssertEquivalencyUsing(options =>
                options.Excluding(member => member.Name == nameof(LinterOutput.DocumentationUrl)));
        }
    }
}
