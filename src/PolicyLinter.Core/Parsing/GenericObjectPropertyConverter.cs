// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

#nullable disable
namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Parsing
{
    using System;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Custom JSON parser for GenericObjectProperty type
    /// </summary>
    internal class GenericObjectPropertyConverter : JsonConverter
    {
        /// <summary>
        /// JSON load settings used for JSON parsing.
        /// </summary>
        private static JsonLoadSettings JsonLoadSettings = new JsonLoadSettings
        {
            LineInfoHandling = LineInfoHandling.Load,
            DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error  // We should error out when there are duplicate properties, per CodeQL [SM04507] Unsafe DuplicatePropertyNameHandling
        };

        /// <summary>
        /// Gets a value indicating whether this converter can write JSON.
        /// </summary>
        public override bool CanWrite => false;

        /// <summary>
        /// Determines whether this instance can convert the specified object type.
        /// </summary>
        /// <param name="objectType">The type of the object to convert.</param>
        public override bool CanConvert(Type objectType)
        {
            return objectType.GenericTypeArguments.Length == 1 &&
                typeof(GenericObjectProperty<>).MakeGenericType(objectType.GenericTypeArguments[0]).IsAssignableFrom(objectType);
        }

        /// <summary>
        /// Reads the JSON representation of the object.
        /// </summary>
        /// <param name="reader">The <see cref="JsonReader"/> to read from.</param>
        /// <param name="receivingProperty">Type of the object.</param>
        /// <param name="existingValue">The existing value of object being read.</param>
        /// <param name="serializer">The calling serializer.</param>
        /// <returns>The object value.</returns>
        public override object ReadJson(JsonReader reader, Type receivingProperty, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.Null)
            {
                return null;
            }

            var token = JToken.Load(reader, GenericObjectPropertyConverter.JsonLoadSettings);

            // TODO: Consider using fast activator from resource stack.
            var propertyObject = (JTokenMetadata)Activator.CreateInstance(receivingProperty);
            var propName = nameof(GenericObjectProperty<object>.Value);
            var value = receivingProperty.GetProperty(propName);

            var receivingType = receivingProperty.GenericTypeArguments[0];
            var coercedValue = token.ToObject(receivingType, serializer);
            value.SetValue(propertyObject, coercedValue);

            propertyObject.LineNumber = (token as IJsonLineInfo).LineNumber;
            propertyObject.LinePosition = (token as IJsonLineInfo).LinePosition;
            return propertyObject;
        }

        /// <summary>
        /// Writes the JSON representation of the object.
        /// </summary>
        /// <param name="writer">The <see cref="JsonWriter"/> to write to.</param>
        /// <param name="value">The value.</param>
        /// <param name="serializer">The calling serializer.</param>
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            throw new NotImplementedException();
        }
    }
}
