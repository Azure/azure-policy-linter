// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// The shape of the effect details, detected from their JSON structure (never from the effect value).
    /// </summary>
    public enum EffectDetailsKind
    {
        /// <summary>
        /// The details don't match any control-plane effect details shape.
        /// </summary>
        Unknown,

        /// <summary>
        /// An array of field/value entries (append).
        /// </summary>
        Append,

        /// <summary>
        /// An object with 'type' (auditIfNotExists, or deployIfNotExists when 'deployment' is set).
        /// </summary>
        IfNotExists,

        /// <summary>
        /// An object with 'operations' (modify).
        /// </summary>
        Modify,

        /// <summary>
        /// An object with 'actionNames' (denyAction).
        /// </summary>
        Action,

        /// <summary>
        /// An empty object, or an object with only 'defaultState' (manual).
        /// </summary>
        Manual,
    }

    /// <summary>
    /// Represents the effect details ("then.details") of a policy rule.
    /// Only the typed details that match <see cref="Kind"/> are set. None are set when the kind is <see cref="EffectDetailsKind.Unknown"/>.
    /// </summary>
    public class EffectDetails : PolicyExpression
    {
        /// <summary>
        /// The shape of the details.
        /// </summary>
        public EffectDetailsKind Kind { get; }

        /// <summary>
        /// The raw details. Expressions in it are not visited.
        /// </summary>
        public JToken Raw { get; }

        /// <summary>
        /// The append details, when <see cref="Kind"/> is <see cref="EffectDetailsKind.Append"/>.
        /// </summary>
        public AppendDetails? Append { get; }

        /// <summary>
        /// The auditIfNotExists or deployIfNotExists details, when <see cref="Kind"/> is <see cref="EffectDetailsKind.IfNotExists"/>.
        /// </summary>
        public IfNotExistsDetails? IfNotExists { get; }

        /// <summary>
        /// The modify details, when <see cref="Kind"/> is <see cref="EffectDetailsKind.Modify"/>.
        /// </summary>
        public ModifyDetails? Modify { get; }

        /// <summary>
        /// The denyAction details, when <see cref="Kind"/> is <see cref="EffectDetailsKind.Action"/>.
        /// </summary>
        public ActionDetails? Action { get; }

        /// <summary>
        /// The manual details, when <see cref="Kind"/> is <see cref="EffectDetailsKind.Manual"/>.
        /// </summary>
        public ManualDetails? Manual { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="EffectDetails"/> class.
        /// </summary>
        /// <param name="details">The raw effect details.</param>
        /// <param name="parentPath">The path of the parent of the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public EffectDetails(
            GenericObjectProperty<JToken> details,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(details.LineNumber, details.LinePosition, parentPath.Add("details"), parent)
        {
            this.Raw = details.Value;
            this.Kind = EffectDetails.GetKind(details: details.Value);

            switch (this.Kind)
            {
                case EffectDetailsKind.Append:
                    this.Append = new AppendDetails(
                        details: EffectDetails.Convert<GenericObjectProperty<AppendEntryObject>[]>(details: details.Value),
                        path: this.PathSegments,
                        parent: this,
                        typeMetadata: typeMetadata);
                    break;
                case EffectDetailsKind.IfNotExists:
                    this.IfNotExists = new IfNotExistsDetails(
                        details: EffectDetails.Convert<IfNotExistsDetailsObject>(details: details.Value),
                        path: this.PathSegments,
                        parent: this,
                        typeMetadata: typeMetadata);
                    break;
                case EffectDetailsKind.Modify:
                    this.Modify = new ModifyDetails(
                        details: EffectDetails.Convert<ModifyDetailsObject>(details: details.Value),
                        path: this.PathSegments,
                        parent: this,
                        typeMetadata: typeMetadata);
                    break;
                case EffectDetailsKind.Action:
                    this.Action = new ActionDetails(
                        details: EffectDetails.Convert<ActionDetailsObject>(details: details.Value),
                        path: this.PathSegments,
                        parent: this,
                        typeMetadata: typeMetadata);
                    break;
                case EffectDetailsKind.Manual:
                    this.Manual = new ManualDetails(
                        details: EffectDetails.Convert<ManualDetailsObject>(details: details.Value),
                        path: this.PathSegments,
                        parent: this,
                        typeMetadata: typeMetadata);
                    break;
            }
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
            this.Append?.Visit(visitor);
            this.IfNotExists?.Visit(visitor);
            this.Modify?.Visit(visitor);
            this.Action?.Visit(visitor);
            this.Manual?.Visit(visitor);
        }

        /// <summary>
        /// Detects the details shape the same way the policy service infers a parameterized control-plane effect.
        /// </summary>
        private static EffectDetailsKind GetKind(JToken details)
        {
            if (details is JArray)
            {
                return EffectDetailsKind.Append;
            }

            if (details is not JObject detailsObject)
            {
                return EffectDetailsKind.Unknown;
            }

            bool Has(string name) => detailsObject.GetValue(propertyName: name, comparison: StringComparison.OrdinalIgnoreCase) != null;

            if (Has("type"))
            {
                return EffectDetailsKind.IfNotExists;
            }

            if (Has("operations"))
            {
                return EffectDetailsKind.Modify;
            }

            if (Has("actionNames"))
            {
                return EffectDetailsKind.Action;
            }

            if (detailsObject.Count == 0 || (detailsObject.Count == 1 && Has("defaultState")))
            {
                return EffectDetailsKind.Manual;
            }

            return EffectDetailsKind.Unknown;
        }

        /// <summary>
        /// Converts the raw details to a parsing object with line info.
        /// </summary>
        private static GenericObjectProperty<T> Convert<T>(JToken details)
        {
            return details.ToObject<GenericObjectProperty<T>>(jsonSerializer: PolicySerializerSettings.Serializer)!;
        }
    }
}
