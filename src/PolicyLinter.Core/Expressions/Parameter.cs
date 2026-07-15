// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Immutable;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Represents a policy parameter definition.
    /// </summary>
    public class Parameter : PolicyExpression
    {
        /// <summary>
        /// The parameter name.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The parameter type.
        /// </summary>
        public string Type { get; }

        /// <summary>
        /// The parameter allowed values.
        /// </summary>
        public JToken[]? AllowedValues { get; }

        /// <summary>
        /// The parameter default value.
        /// </summary>
        public JToken? DefaultValue { get; set; }

        /// <summary>
        /// The parameter metadata object.
        /// </summary>
        public JToken? Metadata { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="Parameter"/> class.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="parameterProperty">The parameter definition.</param>
        /// <param name="path">The parameter expression path.</param>
        /// <param name="parent">The parent policy expressions.</param>
        public Parameter(
            string name,
            GenericObjectProperty<ParameterObject> parameterProperty,
            ImmutableArray<string> path,
            PolicyExpression parent) : base(parameterProperty?.LineNumber, parameterProperty?.LinePosition, path, parent)
        {
            if (parameterProperty == null)
            {
                throw new ArgumentNullException(nameof(parameterProperty), "Parameter definition cannot be null.");
            }

            var parameter = parameterProperty.Value;
            this.Name = name;
            this.Type = parameter.Type?.Value ?? throw new ArgumentNullException(nameof(parameterProperty), "Parameter type cannot be null.");
            this.AllowedValues = parameter.AllowedValues?.Value.Select(v => v.Value).ToArray();

            if (parameter.DefaultValue != null)
            {
                this.DefaultValue = parameter.DefaultValue.Value;
            }

            this.Metadata = parameter.Metadata?.Value;
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
        }

        /// <summary>
        /// Try to convert the parameter allowed values and default value to a concrete type.
        /// </summary>
        /// <param name="allowedValues">The allowed values.</param>
        /// <param name="defaultValue">The default values.</param>
        public bool TryAsConcreteType<T>(out T[]? allowedValues, out T? defaultValue)
        {
            if ((typeof(T) == typeof(string) && this.Type.EqualsOrdinalInsensitively(PolicyParameterType.String)) ||
                (typeof(T) == typeof(int) && this.Type.EqualsOrdinalInsensitively(PolicyParameterType.Integer)) ||
                (typeof(T) == typeof(double) && this.Type.EqualsOrdinalInsensitively(PolicyParameterType.Float)) ||
                (typeof(T) == typeof(float) && this.Type.EqualsOrdinalInsensitively(PolicyParameterType.Float)) ||
                (typeof(T) == typeof(DateTime) && this.Type.EqualsOrdinalInsensitively(PolicyParameterType.DateTime)) ||
                (typeof(T) == typeof(JArray) && this.Type.EqualsOrdinalInsensitively(PolicyParameterType.Array)) ||
                (typeof(T) == typeof(JObject) && this.Type.EqualsOrdinalInsensitively(PolicyParameterType.Object)))
            {
                // TODO: Better casing of array types.
                allowedValues = this.AllowedValues?.Select(x => x.FromJToken<T>()).ToArray();
                defaultValue = this.DefaultValue != null ? this.DefaultValue.FromJToken<T>() : default;
                return true;
            }

            allowedValues = null;
            defaultValue = default;
            return false;
        }
    }

    /// <summary>
    /// The policy parameter type.
    /// </summary>
    public static class PolicyParameterType
    {
        /// <summary>
        /// The policy parameter type is not specified.
        /// </summary>
        public const string NotSpecified = "NotSpecified";

        /// <summary>
        /// The parameter type is string.
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", Justification = "Parameter types mimic C# type names")]
        public const string String = "String";

        /// <summary>
        /// The parameter type is JSON array.
        /// </summary>
        public const string Array = "Array";

        /// <summary>
        /// The parameter type is JSON object.
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", Justification = "Parameter types mimic C# type names")]
        public const string Object = "Object";

        /// <summary>
        /// The parameter type is Boolean.
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", Justification = "Parameter types mimic C# type names")]
        public const string Boolean = "Boolean";

        /// <summary>
        /// The parameter type is Integer.
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", Justification = "Parameter types mimic C# type names")]
        public const string Integer = "Integer";

        /// <summary>
        /// The parameter type is Float.
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", Justification = "Parameter types mimic C# type names")]
        public const string Float = "Float";

        /// <summary>
        /// The parameter type is DateTime as a string
        /// </summary>
        [SuppressMessage("Microsoft.Naming", "CA1720:IdentifiersShouldNotContainTypeNames", Justification = "Parameter types mimic C# type names")]
        public const string DateTime = "DateTime";
    }
}
