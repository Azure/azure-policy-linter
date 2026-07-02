// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts
{
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;

    /// <summary>
    /// Contains context information that is passed to the rule when it is evaluated.
    /// </summary>
    public class LinterContext
    {
        /// <summary>
        /// Gets or sets the resource type metadata.
        /// </summary>
        public ITypeMetadata ResourceTypeMetadata { get; }

        /// <summary>
        /// Gets or sets the optional parameters.
        /// </summary>
        public ImmutableDictionary<string, Parameter>? Parameters { get; set; }

        /// <summary>
        /// Gets or sets the external evaluation enforcement settings.
        /// </summary>
        public ExternalEvaluationEnforcementSettings? ExternalEvaluationEnforcementSettings { get; set; }

        /// <summary>
        /// Gets or sets the optional file path (must be in its full absolute form) of the policy definition being linted.
        /// Can be null if the policy definition is not loaded from a file.
        /// </summary>
        public string? FilePath { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="LinterContext"/> class.
        /// </summary>
        /// <param name="resourceTypeMetadata">The resource type metadata.</param>
        /// <param name="parameters">The optional parameters.</param>
        /// <param name="externalEvaluationEnforcementSettings">The optional external evaluation enforcement settings.</param>
        /// <param name="filePath">The optional file path of the policy definition being linted.</param>
        public LinterContext(
            ITypeMetadata resourceTypeMetadata,
            ImmutableDictionary<string, Parameter>? parameters = null,
            ExternalEvaluationEnforcementSettings? externalEvaluationEnforcementSettings = null,
            string? filePath = null)
        {
            ResourceTypeMetadata = resourceTypeMetadata;
            Parameters = parameters;
            ExternalEvaluationEnforcementSettings = externalEvaluationEnforcementSettings;
            FilePath = filePath;
        }
    }
}
