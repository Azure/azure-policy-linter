// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions.EvaluationHelpers
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using System.Text;
    using System.Web;
    using global::Azure.Deployments.Core.Exceptions;
    using global::Azure.Deployments.Core.Extensions;
    using global::Azure.Deployments.Core.Json.Exceptions;
    using global::Azure.Deployments.Expression.Exceptions;
    using global::Azure.Deployments.Expression.Extensions;
    using global::Azure.Deployments.Expression.Utility;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Extensions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Algorithms;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Microsoft.WindowsAzure.ResourceStack.Common.Json;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

#pragma warning disable CS8602 // Dereference of a possibly null reference.
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.

    /// <summary>
    /// The language expression built-in functions. This code is largely ported from the Azure Policy evaluation engine implementation to ensure parity.
    /// </summary>
    /// <remarks>
    /// This implementation differs from the Azure Policy implementation in that it doesn't have the exact error messages and has less strict evaluation "cost" limits.
    /// Note that this means that new functions added to Azure policy may not be immediately available here until they are ported.
    /// </remarks>
    public class ExpressionBuiltInFunctions
    {
        /// <summary>
        /// The UUID namespace to use for generating string-based deterministic UUID v5 instances.
        /// </summary>
        public static readonly Guid ARMNamespaceGuid = new("11fb06fb-712d-4ddd-98c7-e71bbd588830");

        /// <summary>
        /// The 'data' URI schema prefix.
        /// </summary>
        private static readonly string DataUriSchemaPrefix = "data:";

        /// <summary>
        /// The format() function allowed argument types.
        /// </summary>
        private static readonly ImmutableHashSet<JTokenType> AllowedFormatStringArgumentTypes = new[] { JTokenType.Array, JTokenType.Boolean, JTokenType.Date, JTokenType.Float, JTokenType.Guid, JTokenType.Integer, JTokenType.Null, JTokenType.Object, JTokenType.String, JTokenType.TimeSpan, JTokenType.Undefined, JTokenType.Uri }.ToImmutableHashSet();

        /// <summary>
        /// The allowed argument types when performing tryGet.
        /// </summary>
        private static readonly JTokenType[] TryGetAllowedArgumentTypes = new JTokenType[] { JTokenType.String, JTokenType.Integer };

        /// <summary>
        /// Gets or sets the language expression built-in functions.
        /// </summary>
        protected OrdinalInsensitiveDictionary<Func<string, JToken[], JToken>> BuiltInFunctions { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExpressionBuiltInFunctions"/> class.
        /// </summary>
        public ExpressionBuiltInFunctions()
        {
            this.BuiltInFunctions = new OrdinalInsensitiveDictionary<Func<string, JToken[], JToken>>
            {
                { "concat",                 (function, parameters) => ExpressionBuiltInFunctions.ConcatParameters(function: function, parameters: parameters) },
                { "format",                 (function, parameters) => ExpressionBuiltInFunctions.FormatString(function: function, parameters: parameters) },
                { "base64",                 (function, parameters) => ExpressionBuiltInFunctions.GetBase64(function: function, parameters: parameters) },
                { "padLeft",                (function, parameters) => ExpressionBuiltInFunctions.PadLeft(parameters: parameters) },
                { "replace",                (function, parameters) => ExpressionBuiltInFunctions.Replace(function: function, parameters: parameters) },
                { "toLower",                (function, parameters) => ExpressionBuiltInFunctions.ToLower(function: function, parameters: parameters) },
                { "toUpper",                (function, parameters) => ExpressionBuiltInFunctions.ToUpper(function: function, parameters: parameters) },
                { "length",                 (function, parameters) => ExpressionBuiltInFunctions.GetLength(function: function, parameters: parameters) },
                { "split",                  (function, parameters) => ExpressionBuiltInFunctions.Split(function: function, parameters: parameters) },
                { "join",                   (function, parameters) => ExpressionBuiltInFunctions.Join(function: function, parameters: parameters) },
                { "add",                    (function, parameters) => ExpressionBuiltInFunctions.Add(function: function, parameters: parameters) },
                { "sub",                    (function, parameters) => ExpressionBuiltInFunctions.Sub(function: function, parameters: parameters) },
                { "mul",                    (function, parameters) => ExpressionBuiltInFunctions.Mul(function: function, parameters: parameters) },
                { "div",                    (function, parameters) => ExpressionBuiltInFunctions.Div(function: function, parameters: parameters) },
                { "mod",                    (function, parameters) => ExpressionBuiltInFunctions.Mod(function: function, parameters: parameters) },
                { "string",                 (function, parameters) => ExpressionBuiltInFunctions.ConvertToString(function: function, parameters: parameters) },
                { "int",                    (function, parameters) => ExpressionBuiltInFunctions.ConvertToInt(function: function, parameters: parameters) },
                { "uniqueString",           (function, parameters) => ExpressionBuiltInFunctions.UniqueString(function: function, parameters: parameters) },
                { "guid",                   (function, parameters) => ExpressionBuiltInFunctions.Guid(function: function, parameters: parameters) },
                { "trim",                   (function, parameters) => ExpressionBuiltInFunctions.Trim(function: function, parameters: parameters) },
                { "uri",                    (function, parameters) => ExpressionBuiltInFunctions.GetUri(function: function, parameters: parameters) },
                { "substring",              (function, parameters) => ExpressionBuiltInFunctions.Substring(function: function, parameters: parameters) },
                { "take",                   (function, parameters) => ExpressionBuiltInFunctions.Take(function: function, parameters: parameters) },
                { "skip",                   (function, parameters) => ExpressionBuiltInFunctions.Skip(function: function, parameters: parameters) },
                { "empty",                  (function, parameters) => ExpressionBuiltInFunctions.Empty(function: function, parameters: parameters) },
                { "contains",               (function, parameters) => ExpressionBuiltInFunctions.Contains(function: function, parameters: parameters) },
                { "intersection",           (function, parameters) => ExpressionBuiltInFunctions.Intersection(function: function, parameters: parameters) },
                { "union",                  (function, parameters) => ExpressionBuiltInFunctions.Union(function: function, parameters: parameters) },
                { "first",                  (function, parameters) => ExpressionBuiltInFunctions.First(function: function, parameters: parameters) },
                { "last",                   (function, parameters) => ExpressionBuiltInFunctions.Last(function: function, parameters: parameters) },
                { "indexOf",                (function, parameters) => ExpressionBuiltInFunctions.IndexOf(function: function, parameters: parameters) },
                { "lastIndexOf",            (function, parameters) => ExpressionBuiltInFunctions.LastIndexOf(function: function, parameters: parameters) },
                { "startsWith",             (function, parameters) => ExpressionBuiltInFunctions.StartsWith(function: function, parameters: parameters) },
                { "endsWith",               (function, parameters) => ExpressionBuiltInFunctions.EndsWith(function: function, parameters: parameters) },
                { "min",                    (function, parameters) => ExpressionBuiltInFunctions.Min(function: function, parameters: parameters) },
                { "max",                    (function, parameters) => ExpressionBuiltInFunctions.Max(function: function, parameters: parameters) },
                { "range",                  (function, parameters) => ExpressionBuiltInFunctions.Range(function: function, parameters: parameters) },
                { "base64ToString",         (function, parameters) => ExpressionBuiltInFunctions.ConvertBase64ToString(function: function, parameters: parameters) },
                { "base64ToJson",           (function, parameters) => ExpressionBuiltInFunctions.ConvertBase64ToJson(function: function, parameters: parameters) },
                { "uriComponentToString",   (function, parameters) => ExpressionBuiltInFunctions.ConvertUriComponentToString(function: function, parameters: parameters) },
                { "uriComponent",           (function, parameters) => ExpressionBuiltInFunctions.ConvertToUriComponent(function: function, parameters: parameters) },
                { "dataUriToString",        (function, parameters) => ExpressionBuiltInFunctions.ConvertDataUriToString(function: function, parameters: parameters) },
                { "dataUri",                (function, parameters) => ExpressionBuiltInFunctions.ConvertToDataUri(function: function, parameters: parameters) },
                { "array",                  (function, parameters) => ExpressionBuiltInFunctions.ConvertToArray(function: function, parameters: parameters) },
                { "createArray",            (function, parameters) => ExpressionBuiltInFunctions.CreateArray(parameters: parameters) },
                { "coalesce",               (function, parameters) => ExpressionBuiltInFunctions.CoalesceParameters(function: function, parameters: parameters) },
                { "float",                  (function, parameters) => ExpressionBuiltInFunctions.ConvertToFloat(function: function, parameters: parameters) },
                { "bool",                   (function, parameters) => ExpressionBuiltInFunctions.ConvertToBool(function: function, parameters: parameters) },
                { "less",                   (function, parameters) => ExpressionBuiltInFunctions.ComparisonLess(function: function, parameters: parameters) },
                { "lessOrEquals",           (function, parameters) => ExpressionBuiltInFunctions.ComparisonLessOrEquals(function: function, parameters: parameters) },
                { "greater",                (function, parameters) => ExpressionBuiltInFunctions.ComparisonGreater(function: function, parameters: parameters) },
                { "greaterOrEquals",        (function, parameters) => ExpressionBuiltInFunctions.ComparisonGreaterOrEquals(function: function, parameters: parameters) },
                { "equals",                 (function, parameters) => ExpressionBuiltInFunctions.ComparisonEquals(function: function, parameters: parameters) },
                { "json",                   (function, parameters) => ExpressionBuiltInFunctions.ConvertToJson(function: function, parameters: parameters) },
                { "not",                    (function, parameters) => ExpressionBuiltInFunctions.LogicalNot(function: function, parameters: parameters) },
                { "and",                    (function, parameters) => ExpressionBuiltInFunctions.LogicalAnd(function: function, parameters: parameters) },
                { "or",                     (function, parameters) => ExpressionBuiltInFunctions.LogicalOr(function: function, parameters: parameters) },
                { "if",                     (function, parameters) => ExpressionBuiltInFunctions.If(function: function, parameters: parameters) },
                { "true",                   (function, parameters) => ExpressionBuiltInFunctions.True(function: function, parameters: parameters) },
                { "false",                  (function, parameters) => ExpressionBuiltInFunctions.False(function: function, parameters: parameters) },
                { "null",                   (function, parameters) => ExpressionBuiltInFunctions.Null(function: function, parameters: parameters) },
                { "createObject",           (function, parameters) => ExpressionBuiltInFunctions.CreateObject(function: function, parameters: parameters) },
                { "items",                  (function, parameters) => ExpressionBuiltInFunctions.Items(function: function, parameters: parameters) },
                { "tryGet",                 (function, parameters) => ExpressionBuiltInFunctions.TryGet(function: function, parameters: parameters) },
                { "addDays",                (function, parameters) => ExpressionBuiltInFunctions.AddDays(function: function, parameters: parameters)},
                { "utcNow",                 (function, parameters) => ExpressionBuiltInFunctions.UtcNow(function: function, parameters: parameters)},
                { "ipRangeContains",        (function, parameters) => ExpressionBuiltInFunctions.IpRangeContains(function: function, parameters: parameters)}
            };
        }

        /// <summary>
        /// Get the available functions.
        /// </summary>
        public string[] AvailableFunctions()
        {
            return this.BuiltInFunctions.Keys.ToArray();
        }

        /// <summary>
        /// Determines whether specified function is built-in language expression function.
        /// </summary>
        /// <param name="functionName">The function name.</param>
        public bool IsBuiltInFunction(string functionName)
        {
            return this.BuiltInFunctions.ContainsKey(functionName);
        }

        /// <summary>
        /// Evaluates the function.
        /// </summary>
        /// <param name="functionName">The function name.</param>
        /// <param name="parameters">The function parameters.</param>
        public JToken EvaluateFunction(string functionName, JToken[] parameters)
        {
            if (this.BuiltInFunctions.TryGetValue(functionName, out Func<string, JToken[], JToken> functionBody) && functionBody != null)
            {
                return functionBody(functionName, parameters);
            }

            throw new ExpressionException(message: $"Invalid template function: '{functionName}'.");
        }

        #region ConcatParameters

        /// <summary>
        /// Concatenates the parameters.
        /// </summary>
        /// <param name="function">The function name .</param>
        /// <param name="parameters">The function parameters.</param>
        private static JToken ConcatParameters(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParametersAtLeastOne(function: function, parameters: parameters);

            if (parameters.All(parameter => parameter.Type == JTokenType.Array))
            {
                return new JArray(parameters.UnwrapEnumerable());
            }

            var totalStringLength = 0;
            var parameterStrings = new List<string>(capacity: parameters.Length);
            foreach (var parameter in parameters)
            {
                if (parameter.IsTextBasedJTokenType() || parameter.Type == JTokenType.Integer || parameter.Type == JTokenType.Boolean)
                {
                    var parameterAsString = parameter.ToStringValue();

                    totalStringLength += parameterAsString.Length;
                    parameterStrings.Add(parameterAsString);
                }
                else if (parameter.Type != JTokenType.Null)
                {
                    throw new ExpressionException(message: $"Invalid parameters for concat function '{function}'.");
                }
            }

            return string.Concat(parameterStrings.ToArray());
        }

        /// <summary>
        /// Formats a string.
        /// </summary>
        /// <param name="function">The function name .</param>
        /// <param name="parameters">The function parameters.</param>
        private static JToken FormatString(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParametersAtLeastOne(function: function, parameters: parameters);

            var format = parameters.First();
            var arguments = parameters.Skip(1).ToArray();

            if (format.Type != JTokenType.String || arguments.Any(argument => !ExpressionBuiltInFunctions.AllowedFormatStringArgumentTypes.Contains(argument.Type)))
            {
                throw new ExpressionException(
                    message: "Invalid parameter type for format function.");
            }

            var stringFormat = format.ToStringValue();
            try
            {
                // Note(elpere):
                // Using string builder will help failing the operation in the middle if the resulted string gets too big (without allocating all the memory).
                // In addition, looks like string builder performs better than String.Format in some cases.
                var builder = new StringBuilder(capacity: stringFormat.Length);

                // Note(elpere):
                // Ideally we should combine the 'transformation' of the arguments with the argument type check above.
                // However, there's something in the implicit conversion between the transformed JToken to string that we can't reproduce by regularly converting to JToken to string value.
                // Things like Guids and custom date formats don't work and I don't have time to investigate (it's covered by the existing UTs).
                var stringArgs = arguments.SelectArray(argument => ExpressionBuiltInFunctions.TransformJTokenForOutput(token: argument));

                return builder.AppendFormat(format: stringFormat, args: stringArgs).ToString();
            }
            catch (ArgumentOutOfRangeException)
            {
                throw new ExpressionException(message: $"Template literal limit exceeded.");
            }
            catch (FormatException ex)
            {
                throw new ExpressionException(
                    message: $"Invalid format function parameter: {ex.Message}");
            }
        }

        /// <summary>
        /// Transforms for output.
        /// </summary>
        /// <param name="token">The JToken object.</param>
        private static JToken TransformJTokenForOutput(JToken token)
        {
            // NOTE(wayan): Formatting.None is to make Array and Object to be in a single line.
            return token.Type is JTokenType.Array or JTokenType.Object
                ? token.ToString(Formatting.None).Replace('\"', '\'')
                : token;
        }

        #endregion

        /// <summary>
        /// Validates the number of arguments.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The input parameters.</param>
        /// <param name="count">The expected number of arguments.</param>
        private static void ValidateParameterCount(string function, JToken[] parameters, int count)
        {
            int argCount = parameters.CoalesceEnumerable().Count();
            if (argCount != count)
            {
                throw new BuiltinFunctionNumberOfParametersException($"Function '{function}' expects {count} parameters but received {argCount} parameters.", additionalInfo: null);
            }
        }

        /// <summary>
        /// Validates the number of arguments is at least one.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The input parameters.</param>
        private static void ValidateParametersAtLeastOne(string function, JToken[] parameters)
        {
            int argCount = parameters.CoalesceEnumerable().Count();
            if (argCount < 1)
            {
                throw new BuiltinFunctionNumberOfParametersException($"Function '{function}' expects at least 1 parameter but received {argCount} parameters.", additionalInfo: null);
            }
        }

        /// <summary>
        /// Validates the number of arguments is at least two.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The input parameters.</param>
        private static void ValidateParametersAtLeastTwo(string function, JToken[] parameters)
        {
            int argCount = parameters.CoalesceEnumerable().Count();
            if (argCount < 2)
            {
                throw new BuiltinFunctionNumberOfParametersException($"Function '{function}' expects at least 2 parameters but received {argCount} parameters.", additionalInfo: null);
            }
        }

        /// <summary>
        /// Validates the number of arguments is even. Allows zero arguments.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The input parameters.</param>
        private static void ValidateEvenNumberOfParameters(string function, JToken[] parameters)
        {
            int argCount = parameters.CoalesceEnumerable().Count();
            if (argCount % 2 != 0)
            {
                throw new BuiltinFunctionNumberOfParametersException($"Function '{function}' expects an even number of parameters but received {argCount} parameters.", additionalInfo: null);
            }
        }

        /// <summary>
        /// Validates that given parameters are of the same type.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The input parameters.</param>
        private static void ValidateSingleParameterType(string function, JToken[] parameters)
        {
            var parameterTypes = parameters.DistinctArray(parameter => parameter.Type);
            if (parameterTypes.Length > 1)
            {
                throw new ExpressionException($"Function '{function}' expects all parameters to be of the same type but received different types.", additionalInfo: null);
            }
        }

        /// <summary>
        /// Validates that given parameters are of numeric type.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The input parameters.</param>
        private static void ValidateAllParametersNumeric(string function, JToken[] parameters)
        {
            var invalidParameterTypes = parameters
                .Where(parameter => parameter.Type is not JTokenType.Integer and not JTokenType.Float);

            if (invalidParameterTypes.Any())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects numeric parameters.");
            }
        }

        /// <summary>
        /// Validates that given parameters are of boolean type.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The input parameters.</param>
        private static void ValidateAllParametersBoolean(string function, JToken[] parameters)
        {
            var invalidParameterTypes = parameters
                .Where(parameter => parameter.Type != JTokenType.Boolean);

            if (invalidParameterTypes.Any())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects boolean parameters.");
            }
        }

        /// <summary>
        /// Validates that the indexed parameter is of the allowed type.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameter">The input parameters.</param>
        /// <param name="index">The index.</param>
        /// <param name="allowedTypes">The allowed types.</param>
        private static void ValidateIndexedParameterMultipleAllowedTypes(string function, JToken parameter, int index, params JTokenType[] allowedTypes)
        {
            if (!(parameter?.Type is JTokenType parameterType && allowedTypes.Contains(parameterType)))
            {
                throw new ExpressionException(
                    message: $"Invalid parameter type for function '{function}' at parameter {index}.");
            }
        }

        /// <summary>
        /// Validates if the parameter is a date and parses it
        /// </summary>
        /// <param name="parameter">The parameter.</param>
        private static DateTime ValidateAndParseDateParameter(JToken parameter)
        {
            if (!parameter.TryFromJToken<string>().TryParseISO8601UniversalDateTime(out var parsedDate))
            {
                throw new ExpressionException($"Invalid parameter: {parameter}");
            }

            return parsedDate;
        }

        /// <summary>
        /// Validates if the JToken parameter is of integer type and parses it
        /// </summary>
        /// <param name="parameter">The parameter.</param>
        private static int ValidateAndParseIntegerParameter(JToken parameter)
        {
            if (parameter.Type != JTokenType.Integer)
            {
                throw new ExpressionException($"Invalid integer parameter: {parameter}");
            }

            return parameter.TryFromJToken<int>();
        }

        /// <summary>
        /// Creates a JToken[] if there is only one parameter and its of type JArray.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        private static JToken[] UnwrapParameters(JToken[] parameters)
        {
            return parameters.CoalesceEnumerable().Count() == 1 && parameters[0].Type == JTokenType.Array
                ? parameters[0].ToObject<JToken[]>()!
                : parameters;
        }

        /// <summary>
        /// Creates a data URI.
        /// </summary>
        /// <param name="contentType">The content type.</param>
        /// <param name="content">The base64 encoded content.</param>
        private static JValue CreateDataUri(string contentType, string content)
        {
            return JValue.CreateString($"{ExpressionBuiltInFunctions.DataUriSchemaPrefix}{(!string.IsNullOrWhiteSpace(contentType) ? contentType : "application/octet-stream")};base64,{content}");
        }

        /// <summary>
        /// Gets the single string parameter.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        internal static string GetSingleStringParameter(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 1)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Too many parameters for function '{function}'.", additionalInfo: null);
            }

            var parameter = parameters.Single();
            if (parameter.Type != JTokenType.String && parameter.Type != JTokenType.Null)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects a string parameter.");
            }

            return parameter.ToString();
        }

        /// <summary>
        /// Safely dereferences a property from a JObject or JArray based on the property type, returning null if the property is not found.
        /// </summary>
        /// <param name="root">The root JToken (JObject or JArray).</param>
        /// <param name="property">The property to dereference.</param>
        private static JToken PerformSafeDereference(JToken root, JToken property)
        {
            return root switch
            {
                JObject jObject when property.IsTextBasedJTokenType() && jObject.TryGetValue(property.ToObject<string>()!, StringComparison.InvariantCultureIgnoreCase, out var value) => value,
                JArray jArray when property.Type == JTokenType.Integer && (int)property is int arrayIndex && 0 <= arrayIndex && arrayIndex < jArray.Count => jArray[arrayIndex],
                _ => JValue.CreateNull()
            };
        }

        /// <summary>
        /// Performs chained dereferences on a root JToken using a series of parameters.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="root">The root JToken to start dereferencing from.</param>
        /// <param name="parameters">The parameters used for dereferencing.</param>
        private static JToken PerformChainedDereferences(string function, JToken root, JToken[] parameters)
        {
            if (root == null || root.IsNullishJTokenType())
            {
                return JValue.CreateNull();
            }

            FunctionResult functionResult = new JTokenSelectableFunctionResult(root);

            for (int i = 2; i < parameters.Length; i++)
            {
                ExpressionBuiltInFunctions.ValidateIndexedParameterMultipleAllowedTypes(
                    function: function,
                    parameter: parameters[i],
                    index: i,
                    allowedTypes: ExpressionBuiltInFunctions.TryGetAllowedArgumentTypes);

                functionResult = functionResult.SelectProperty(property: parameters[i]);
            }

            return functionResult.CurrentValue();
        }

        #region GetBase64

        /// <summary>
        /// Encodes the input parameter into base64 string
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The function parameters.</param>
        private static JValue GetBase64(string function, JToken[] parameters)
        {
            var stringParameter = ExpressionBuiltInFunctions.GetSingleStringParameter(function, parameters);
            var value = stringParameter.EncodeToBase64String();

            return JValue.CreateString(value);
        }

        #endregion

        #region PadLeft

        /// <summary>
        /// Padding the input string with specified characters on the left, for a specified total length.
        /// </summary>
        /// <param name="parameters">The function parameters.</param>
        private static JToken PadLeft(JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2 && parameters.CoalesceEnumerable().Count() != 3)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Invalid parameter count for padLeft function: {parameters.CoalesceEnumerable().Count()}.", additionalInfo: null);
            }

            if (parameters[0].Type != JTokenType.Integer && !parameters[0].IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: "Invalid first parameter type for padLeft function.");
            }

            return parameters[0]
                    .ToObject<string>()
                    .CoalesceString()
                    .PadLeft(
                        totalWidth: ExpressionBuiltInFunctions.GetPaddingWidthParameter(parameters),
                        paddingChar: ExpressionBuiltInFunctions.GetPaddingCharacterParameter(parameters));
        }

        /// <summary>
        /// Gets the padding width from parameters.
        /// </summary>
        /// <param name="parameters">The function parameters.</param>
        private static int GetPaddingWidthParameter(JToken[] parameters)
        {
            if (parameters[1].Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: "Invalid second parameter type for padLeft function. Expected integer.");
            }

            const int MaximumWidth = 16;
            var totalWidth = parameters[1].ToObject<int>();
            if (totalWidth <= 0 || totalWidth > MaximumWidth)
            {
                throw new ExpressionException(
                    message: $"Invalid padding width for padLeft function: {totalWidth}. Must be between 1 and {MaximumWidth}.");
            }

            return totalWidth;
        }

        /// <summary>
        /// Gets the padding character from parameters.
        /// </summary>
        /// <param name="parameters">The function parameters.</param>
        private static char GetPaddingCharacterParameter(JToken[] parameters)
        {
            if (parameters.Length == 3 && parameters[2].Type != JTokenType.Null)
            {
                if (!parameters[2].IsTextBasedJTokenType())
                {
                    throw new ExpressionException(
                        message: "Invalid third parameter type for padLeft function. Expected string.");
                }

                if (parameters[2].ToObject<string>().Length != 1)
                {
                    throw new ExpressionException(
                        message: "Invalid padding character for padLeft function. Must be a single character.");
                }

                return parameters[2].ToObject<string>()!.SingleOrDefault();
            }

            return ' ';
        }

        #endregion

        #region Replace

        /// <summary>
        /// Gets a string in which all occurrences of one string are replaced with another string.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Replace(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 3)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 3 parameters.", additionalInfo: null);
            }

            var parameter1 = parameters[0];
            var parameter2 = parameters[1];
            var parameter3 = parameters[2];

            if (!parameter1.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects first parameter to be a string.");
            }

            if (!parameter2.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects second parameter to be a string.");
            }

            if (!parameter3.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects third parameter to be a string.");
            }

            var oldString = parameter2.ToStringValue();
            if (string.IsNullOrEmpty(oldString))
            {
                throw new ExpressionException(message: $"Function '{function}' second parameter cannot be empty.");
            }

            var stringParameter = parameter1.ToStringValue();
            if (string.IsNullOrEmpty(stringParameter))
            {
                return stringParameter;
            }

            var newString = parameter3.ToStringValue();

            return stringParameter.Replace(oldString, newString, StringComparison.InvariantCultureIgnoreCase);
        }

        #endregion

        #region ToLower

        /// <summary>
        /// Converts string to the lower casing.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Globalization", "CA1308:NormalizeStringsToUppercase", Justification = "By design.")]
        private static JToken ToLower(string function, JToken[] parameters)
        {
            return ExpressionBuiltInFunctions
                .GetSingleStringParameter(function, parameters)
                .ToLowerInvariant();
        }

        #endregion

        #region ToUpper

        /// <summary>
        /// Converts string to the upper casing.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ToUpper(string function, JToken[] parameters)
        {
            return ExpressionBuiltInFunctions
                .GetSingleStringParameter(function, parameters)
                .ToUpperInvariant();
        }

        #endregion

        #region GetLength

        /// <summary>
        /// Gets the length.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken GetLength(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 1)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' has invalid parameter count.", additionalInfo: null);
            }

            var parameter = parameters.Single();
            switch (parameter.Type)
            {
                case JTokenType.Null:
                    return 0;

                case JTokenType.Array:
                case JTokenType.Object:
                    return parameter.Count();

                case JTokenType.String:
                case JTokenType.Uri:
                    return parameter.ToObject<string>().Length;

                default:
                    throw new ExpressionException(
                        message: $"Function '{function}' received invalid parameter type.");
            }
        }

        #endregion

        #region Trim

        /// <summary>
        /// Trims the string.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Trim(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 1)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 1 parameter.", additionalInfo: null);
            }

            var parameter = parameters.Single();
            if (!parameter.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects a string parameter.");
            }

            return parameter.ToObject<string>().CoalesceString().Trim();
        }

        #endregion

        #region Split

        /// <summary>
        /// Splits the string.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Split(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 2 parameters.",
                    additionalInfo: null);
            }

            var input = parameters[0];
            var delimiter = parameters[1];

            if (!input.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects first parameter to be a string.");
            }

            if (input.Type == JTokenType.Null)
            {
                return new JArray();
            }

            var inputString = input.ToStringValue()!;

            switch (delimiter.Type)
            {
                case JTokenType.Array:
                    var invalidDelimiters = delimiter.Where(member => !member.IsTextBasedJTokenType()).ToArray();
                    if (invalidDelimiters.Any())
                    {
                        var invalidTypes = invalidDelimiters.DistinctInsensitively(
                            keySelector: invalidDelimiter => invalidDelimiter.Type.ToString(),
                            resultSelector: invalidDelimiter => invalidDelimiter.Type.ToString());

                        throw new ExpressionException(
                            message: $"Function '{function}' expects second parameter to be string or array of strings.");
                    }

                    return ExpressionBuiltInFunctions.Split(inputString, delimiter.ToObject<string[]>()!);

                case JTokenType.String:
                case JTokenType.Uri:
                    return ExpressionBuiltInFunctions.Split(inputString, delimiter.ToObject<string>()!);

                case JTokenType.Null:
                    return new JArray(inputString);

                default:
                    throw new ExpressionException(
                        message: $"Function '{function}' expects second parameter to be string or array of strings.");
            }
        }

        /// <summary>
        /// Splits the string.
        /// </summary>
        /// <param name="inputString">The input string.</param>
        /// <param name="delimiters">The delimiters.</param>
        private static JToken Split(string inputString, params string[] delimiters)
        {
            return inputString.Split(delimiters, StringSplitOptions.None).ToJToken();
        }

        #endregion

        #region Join

        /// <summary>
        /// Joins an array of strings into a string, with a given delimiter.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Join(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 2 parameters.",
                    additionalInfo: null);
            }

            var inputArrayArg = parameters[0];
            var delimiterArg = parameters[1];
            if (inputArrayArg?.Type != JTokenType.Array)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects first parameter to be an array.");
            }

            if (!delimiterArg.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects second parameter to be a string.");
            }

            OrdinalInsensitiveHashSet invalidTypes = null;
            StringBuilder invalidIndices = null;
            int newStringLength = 0;
            var inputArray = inputArrayArg.ToArray();
            for (var i = 0; i < inputArray.Length; ++i)
            {
                if (inputArray[i].IsTextBasedJTokenType())
                {
                    newStringLength += inputArray[i].ToStringValue().Length;
                }
                else
                {
                    invalidTypes ??= new OrdinalInsensitiveHashSet();
                    _ = invalidTypes.Add(inputArray[i].Type.ToString());

                    invalidIndices ??= new StringBuilder();
                    if (invalidIndices.Length > 0)
                    {
                        _ = invalidIndices.Append(", ");
                    }

#pragma warning disable CA1830 // Prefer strongly-typed Append and Insert method overloads on StringBuilder
                    _ = invalidIndices.Append(i.ToString());
#pragma warning restore CA1830 // Prefer strongly-typed Append and Insert method overloads on StringBuilder
                }
            }

            var delimiter = delimiterArg.ToStringValue();
            newStringLength += delimiter.Length * (inputArray.Length > 0 ? inputArray.Length - 1 : 0);

            if (invalidTypes != null)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' first parameter array contains invalid element types.");
            }

            // Use StringBuilder instead of string.Join to save the space for a string array of input elements which will be used as parameter and another calculation of total new string length in string.Join.
            var newString = new StringBuilder(capacity: newStringLength);
            for (var i = 0; i < inputArray.Length; ++i)
            {
                if (i > 0)
                {
                    _ = newString.Append(delimiter);
                }

                _ = newString.Append(inputArray[i].ToStringValue());
            }

            return newString.ToString().ToJToken();
        }

        #endregion Join

        #region Add

        /// <summary>
        /// Gets the addition of two numbers.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Add(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 2 parameters.",
                    additionalInfo: null);
            }

            var operand1 = parameters[0];
            var operand2 = parameters[1];

            if (operand1.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects first parameter to be an integer.");
            }

            if (operand2.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects second parameter to be an integer.");
            }

            try
            {
                return checked(operand1.ToObject<long>() + operand2.ToObject<long>());
            }
            catch (OverflowException)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' detected overflow.");
            }
        }

        #endregion

        #region Sub

        /// <summary>
        /// Gets the subtraction of two numbers.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Sub(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 2 parameters.",
                    additionalInfo: null);
            }

            var operand1 = parameters[0];
            var operand2 = parameters[1];

            if (operand1.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects first parameter to be an integer.");
            }

            if (operand2.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects second parameter to be an integer.");
            }

            try
            {
                return checked(operand1.ToObject<long>() - operand2.ToObject<long>());
            }
            catch (OverflowException)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' detected overflow.");
            }
        }

        #endregion

        #region Mul

        /// <summary>
        /// Gets the multiplication of two numbers.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Mul(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 2 parameters.",
                    additionalInfo: null);
            }

            var operand1 = parameters[0];
            var operand2 = parameters[1];

            if (operand1.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects first parameter to be an integer.");
            }

            if (operand2.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects second parameter to be an integer.");
            }

            try
            {
                return checked(operand1.ToObject<long>() * operand2.ToObject<long>());
            }
            catch (OverflowException)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' detected overflow.");
            }
        }

        #endregion

        #region Div

        /// <summary>
        /// Gets the division of two numbers.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Div(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 2 parameters.",
                    additionalInfo: null);
            }

            var operand1 = parameters[0];
            var operand2 = parameters[1];

            if (operand1.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects first parameter to be an integer.");
            }

            if (operand2.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects second parameter to be an integer.");
            }

            var divisor = operand2.ToObject<long>();
            if (divisor == 0)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' cannot divide by zero.");
            }

            try
            {
                return checked(operand1.ToObject<long>() / divisor);
            }
            catch (OverflowException)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' detected overflow.");
            }
        }

        #endregion

        #region Mod

        /// <summary>
        /// Gets the modulo of two numbers.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Mod(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 2 parameters.",
                    additionalInfo: null);
            }

            var operand1 = parameters[0];
            var operand2 = parameters[1];

            if (operand1.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects first parameter to be an integer.");
            }

            if (operand2.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects second parameter to be an integer.");
            }

            var divisor = operand2.ToObject<long>();
            if (divisor == 0)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' cannot divide by zero.");
            }

            try
            {
                return checked(operand1.ToObject<long>() % divisor);
            }
            catch (OverflowException)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' detected overflow.");
            }
        }

        #endregion

        #region ConvertToString

        /// <summary>
        /// Converts parameter to string.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        public static JToken ConvertToString(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 1)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 1 parameter.", additionalInfo: null);
            }

            var parameter = parameters.Single();
            if (!parameter.IsTextBasedJTokenType() &&
                parameter.Type != JTokenType.Integer &&
                parameter.Type != JTokenType.Boolean &&
                parameter.Type != JTokenType.Object &&
                parameter.Type != JTokenType.Array)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects parameter to be Integer, String, Boolean, Object, or Array.");
            }

            if (parameter.Type is JTokenType.Object or JTokenType.Array)
            {
                return parameter.ToJson();
            }
            else if (parameter.Type == JTokenType.Null)
            {
                return string.Empty;
            }

            return parameter.ToObject<string>();
        }

        #endregion

        #region ConvertToInt

        /// <summary>
        /// Converts parameter to an integer.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ConvertToInt(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 1)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 1 parameter.", additionalInfo: null);
            }

            var parameter = parameters.Single();
            if (parameter.Type != JTokenType.Integer && !parameter.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects parameter to be Integer or String.");
            }

            if (!long.TryParse(parameter.ToObject<string>(), out long retVal))
            {
                throw new ExpressionException(
                    message: $"Cannot convert value to integer.");
            }

            return retVal;
        }

        #endregion

        /// <summary>
        /// Join the given string parameters with '-'.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static string JoinStringParametersWithDash(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParametersAtLeastOne(function, parameters);

            var stringParameters = new List<string>(capacity: parameters.Length);
            var totalStringLength = 0;
            foreach (var parameter in parameters)
            {
                if (!parameter.IsTextBasedJTokenType())
                {
                    throw new ExpressionException(
                        message: $"Function '{function}' expects string parameters.");
                }

                var value = parameter.ToStringValue();
                totalStringLength += value.Length;

                stringParameters.Add(value);
            }

            return stringParameters.ConcatStrings("-");
        }

        #region UniqueString

        /// <summary>
        /// Gets a unique lower cased string based on input.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken UniqueString(string function, JToken[] parameters)
        {
            var joinedParameters = ExpressionBuiltInFunctions.JoinStringParametersWithDash(function: function, parameters: parameters);
            return ExpressionBuiltInFunctions.Base32Encode(ComputeHash.MurmurHash64(joinedParameters));
        }

        /// <summary>
        /// Converts 64 bits value to Base32 encoded string.
        /// </summary>
        /// <param name="input">The value to be encoded.</param>
        private static string Base32Encode(ulong input)
        {
            const string charset = "abcdefghijklmnopqrstuvwxyz234567";
            var sb = new StringBuilder();

            for (var index = 0; index < 13; index++)
            {
                _ = sb.Append(charset[(int)(input >> 59)]);
                input <<= 5;
            }

            return sb.ToString();
        }

        #endregion

        #region Guid

        /// <summary>
        /// Gets a deterministic lower-cased UUID v5 based on input and the ARM namespace.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Guid(string function, JToken[] parameters)
        {
            var joinedParameters = ExpressionBuiltInFunctions.JoinStringParametersWithDash(function: function, parameters: parameters);
            return GuidUtility
                .Create(
                    namespaceId: ExpressionBuiltInFunctions.ARMNamespaceGuid,
                    name: joinedParameters,
                    version: 5)
                .ToString();
        }

        #endregion

        #region Uri

        /// <summary>
        /// Gets the uri.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken GetUri(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' expects 2 parameters.", additionalInfo: null);
            }

            if (!parameters.All(parameter => parameter.IsTextBasedJTokenType()))
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects string parameters.");
            }

            var baseUriParameter = parameters[0];
            var relativeUriParameter = parameters[1];

            var baseUriString = baseUriParameter.ToObject<string>().CoalesceString();
            if (!Uri.IsWellFormedUriString(baseUriString, UriKind.Absolute))
            {
                throw new ExpressionException(
                    message: $"Invalid URI format: {baseUriString}.");
            }

            if (!Uri.TryCreate(baseUriParameter.ToObject<Uri>(), relativeUriParameter.ToObject<string>().CoalesceString(), out Uri result))
            {
                throw new ExpressionException(
                    message: "Unable to create URI.");
            }

            return result.AbsoluteUri;
        }

        #endregion

        #region Substring

        /// <summary>
        /// Gets a substring of a longer string.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Substring(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() is < 2 or > 3)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: "Invalid parameter count for substring function.", additionalInfo: null);
            }

            var parameter1 = parameters[0];
            var parameter2 = parameters[1];

            if (!parameter1.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects first parameter to be a string.");
            }

            if (parameter2.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects second parameter to be an integer.");
            }

            var stringParameter = parameter1.ToObject<string>().CoalesceString();
            var startIndex = parameter2.ToObject<int>();

            if (startIndex < 0)
            {
                throw new ExpressionException(
                   message: $"Substring index must be greater than or equal to zero: {startIndex}.");
            }

            if (startIndex > stringParameter.Length)
            {
                throw new ExpressionException(
                    message: "Substring index exceeds string length.");
            }

            if (parameters.Length == 2)
            {
                return stringParameter[startIndex..];
            }

            var parameter3 = parameters[2];
            if (parameter3.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects third parameter to be an integer.");
            }

            var length = parameter3.ToObject<int>();
            if (length < 0)
            {
                throw new ExpressionException(
                    message: "Substring length must be greater than or equal to zero.");
            }

            if (startIndex > stringParameter.Length - length)
            {
                throw new ExpressionException(
                    message: "Substring parameters out of bounds.");
            }

            return stringParameter.Substring(startIndex: startIndex, length: length);
        }

        #endregion

        #region Take

        /// <summary>
        /// Gets first N elements.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Take(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' has invalid parameter count.", additionalInfo: null);
            }

            var parameter1 = parameters[0];
            var parameter2 = parameters[1];

            if (parameter1.Type != JTokenType.Array && !parameter1.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' first parameter has invalid type.");
            }

            if (parameter2.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' second parameter has invalid type.");
            }

            var takeCount = parameter2.ToObject<int>();

            switch (parameter1.Type)
            {
                case JTokenType.Null:
                    return JValue.CreateNull();

                case JTokenType.Array:
                    return new JArray(parameter1.ToObject<JArray>()!.Take(takeCount));

                case JTokenType.String:
                case JTokenType.Uri:
                    var stringParameter = parameter1.ToObject<string>();
                    return string.IsNullOrEmpty(stringParameter)
                        ? string.Empty
                        : new string(stringParameter.Take(takeCount).ToArray());

                default:
                    throw new ExpressionException(
                        message: $"Function '{function}' first parameter has invalid type.");
            }
        }

        #endregion

        #region Skip

        /// <summary>
        /// Gets all elements after N elements.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Skip(string function, JToken[] parameters)
        {
            if (parameters.CoalesceEnumerable().Count() != 2)
            {
                throw new BuiltinFunctionNumberOfParametersException(
                    message: $"Function '{function}' has invalid parameter count.", additionalInfo: null);
            }

            var parameter1 = parameters[0];
            var parameter2 = parameters[1];

            if (parameter1.Type != JTokenType.Array && !parameter1.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' first parameter has invalid type.");
            }

            if (parameter2.Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' second parameter has invalid type.");
            }

            var skipCount = parameter2.ToObject<int>();

            switch (parameter1.Type)
            {
                case JTokenType.Null:
                    return JValue.CreateNull();

                case JTokenType.Array:
                    return new JArray(parameter1.ToObject<JArray>()!.Skip(skipCount));

                case JTokenType.String:
                case JTokenType.Uri:
                    var stringParameter = parameter1.ToObject<string>();
                    return string.IsNullOrEmpty(stringParameter)
                        ? string.Empty
                        : new string(stringParameter.Skip(skipCount).ToArray());

                default:
                    throw new ExpressionException(
                        message: $"Function '{function}' first parameter has invalid type.");
            }
        }

        #endregion

        #region Empty

        /// <summary>
        /// Checks if given argument is empty.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Empty(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            return parameter.Type switch
            {
                JTokenType.Null => (JToken)true,
                JTokenType.Object or JTokenType.Array => (JToken)!parameter.Any(),
                JTokenType.String or JTokenType.Uri => (JToken)string.IsNullOrEmpty(parameter.ToObject<string>()),
                _ => throw new ExpressionException(message: "Invalid parameter type for empty function."),
            };
        }

        #endregion

        #region Contains

        /// <summary>
        /// Checks if the first argument contains the second argument.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Contains(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            var dictionary = parameters[0];
            var element = parameters[1];

            switch (dictionary.Type)
            {
                case JTokenType.Object:
                    if (!element.IsTextBasedJTokenType())
                    {
                        throw new ExpressionException(
                            message: "Invalid parameter types for contains function.");
                    }

                    JToken property = null;
                    return (dictionary as JObject).TryGetValue(element.ToObject<string>()!, StringComparison.InvariantCultureIgnoreCase, out property);

                case JTokenType.Array:
                    return dictionary.Any(item => JToken.DeepEquals(item, element));

                case JTokenType.String:
                case JTokenType.Uri:
                    if (!element.IsTextBasedJTokenType())
                    {
                        throw new ExpressionException(
                            message: "Invalid parameter types for contains function.");
                    }

                    var sourceString = dictionary.ToStringValue();
                    var value = element.ToStringValue();

                    return sourceString.Contains(value!, StringComparison.InvariantCultureIgnoreCase);

                default:
                    throw new ExpressionException(
                        message: "Invalid parameter types for contains function.");
            }
        }

        #endregion

        #region Intersection

        /// <summary>
        /// Gets common elements among several collections.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Intersection(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParametersAtLeastTwo(function, parameters);
            ExpressionBuiltInFunctions.ValidateSingleParameterType(function, parameters);

            return parameters[0].Type switch
            {
                JTokenType.Array => new JArray(parameters
                                        .Cast<JArray>()
                                        .Select(jarray => jarray.Distinct(JToken.EqualityComparer).ToArray())
                                        .SelectMany(array => array)
                                        .CountElements(JToken.EqualityComparer)
                                        .Where(counter => counter.Value == parameters.Length)
                                        .Select(counter => counter.Key)),

                JTokenType.Object => new JObject(parameters
                                        .Cast<JObject>()
                                        .SelectMany(jObject => jObject.Properties())
                                        .CountElements(JToken.EqualityComparer)
                                        .Where(counter => counter.Value == parameters.Length)
                                        .Select(counter => counter.Key)),

                _ => throw new ExpressionException(message: "Invalid parameter types for intersection function."),
            };
        }

        #endregion

        #region Union

        /// <summary>
        /// Gets all elements across several collections.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Union(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParametersAtLeastTwo(function, parameters);
            ExpressionBuiltInFunctions.ValidateSingleParameterType(function, parameters);

            switch (parameters[0].Type)
            {
                case JTokenType.Array:
                    return new JArray(parameters
                        .Cast<JArray>()
                        .SelectMany(jarray => jarray.Children())
                        .Distinct(JToken.EqualityComparer));

                case JTokenType.Object:
                    // NOTE(wayan): JsonExtensions.MergeJsonInsensitive() mutates its first argument 'source' (i.e. merges properties from the second argument 'patch' into it).
                    try
                    {
                        return new JObject()
                            .AsArray()
                            .ConcatArray(parameters)
                            .Aggregate((source, patch) => JsonExtensions.MergeJsonInsensitive(source, patch));
                    }
                    catch (MergeJsonTypeMismatchException exception)
                    {
                        throw new ExpressionException(
                            message: "Invalid parameter types for union function.",
                            innerException: exception);
                    }

                default:
                    throw new ExpressionException(
                        message: "Invalid parameter types for union function.");
            }
        }

        #endregion

        #region First

        /// <summary>
        /// Gets the first element.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken First(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            switch (parameter.Type)
            {
                case JTokenType.Null:
                    return JValue.CreateNull();

                case JTokenType.Array:
                    return parameter.ToObject<JArray>().First ?? JValue.CreateNull();

                case JTokenType.String:
                case JTokenType.Uri:
                    var stringParameter = parameter.ToObject<string>();
                    return !string.IsNullOrEmpty(stringParameter)
                        ? stringParameter.First().ToString()
                        : stringParameter;

                default:
                    throw new ExpressionException(
                        message: "Invalid parameter type for first function.");
            }
        }

        #endregion

        #region Last

        /// <summary>
        /// Gets the last element.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Last(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            switch (parameter.Type)
            {
                case JTokenType.Null:
                    return JValue.CreateNull();

                case JTokenType.Array:
                    return parameter.ToObject<JArray>().Last ?? JValue.CreateNull();

                case JTokenType.String:
                case JTokenType.Uri:
                    var stringParameter = parameter.ToObject<string>();
                    return !string.IsNullOrEmpty(stringParameter)
                        ? stringParameter.Last().ToString()
                        : stringParameter;

                default:
                    throw new ExpressionException(
                        message: "Invalid parameter type for last function.");
            }
        }

        #endregion

        #region IndexOf

        /// <summary>
        /// Finds the index of a value within a string or array.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken IndexOf(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            var container = parameters[0];
            var value = parameters[1];

            switch (container.Type)
            {
                case JTokenType.Null:
                    return -1;

                case JTokenType.Array:
                    var containerArray = container as JArray;
                    for (var i = 0; i < containerArray.Count; i++)
                    {
                        if (JToken.DeepEquals(containerArray[i], value))
                        {
                            return i;
                        }
                    }

                    return -1;

                case JTokenType.String:
                case JTokenType.Uri:
                    if (!value.IsTextBasedJTokenType())
                    {
                        throw new ExpressionException(
                            message: $"Function '{function}' expects second parameter to be a string.");
                    }

                    return container.ToObject<string>().IndexOf(value.ToObject<string>()!, StringComparison.InvariantCultureIgnoreCase);

                default:
                    throw new ExpressionException(
                        message: $"Function '{function}' expects first parameter to be string or array.");
            }
        }

        #endregion

        #region LastIndexOf

        /// <summary>
        /// Finds the last index of a value within a string or array.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken LastIndexOf(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            var container = parameters[0];
            var value = parameters[1];

            switch (container.Type)
            {
                case JTokenType.Null:
                    return -1;

                case JTokenType.Array:
                    var containerArray = container as JArray;
                    for (var i = containerArray.Count - 1; i >= 0; i--)
                    {
                        if (JToken.DeepEquals(containerArray[i], value))
                        {
                            return i;
                        }
                    }

                    return -1;

                case JTokenType.String:
                case JTokenType.Uri:
                    if (!value.IsTextBasedJTokenType())
                    {
                        throw new ExpressionException(
                            message: $"Function '{function}' expects second parameter to be a string.");
                    }

                    return container.ToObject<string>().LastIndexOf(value.ToObject<string>()!, StringComparison.InvariantCultureIgnoreCase);

                default:
                    throw new ExpressionException(
                        message: $"Function '{function}' expects first parameter to be string or array.");
            }
        }

        #endregion

        #region StartsWith

        /// <summary>
        /// Checks if the string starts with a value.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken StartsWith(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            var parameter1 = parameters[0];
            var parameter2 = parameters[1];

            if (!parameter1.IsTextBasedJTokenType() || !parameter2.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects two string parameters.");
            }

            return parameter1.ToObject<string>().CoalesceString().StartsWithInsensitively(parameter2.ToObject<string>());
        }

        #endregion

        #region EndsWith

        /// <summary>
        /// Checks if the string ends with a value.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken EndsWith(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            var parameter1 = parameters[0];
            var parameter2 = parameters[1];

            if (!parameter1.IsTextBasedJTokenType() || !parameter2.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects two string parameters.");
            }

            return parameter1.ToObject<string>().CoalesceString().EndsWithInsensitively(parameter2.ToObject<string>());
        }

        #endregion

        #region Min

        /// <summary>
        /// Gets Min element.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Min(string function, JToken[] parameters)
        {
            parameters = ExpressionBuiltInFunctions.UnwrapParameters(parameters);

            ExpressionBuiltInFunctions.ValidateParametersAtLeastOne(function, parameters);
            ExpressionBuiltInFunctions.ValidateAllParametersNumeric(function, parameters);

            return parameters.Any(parameter => parameter.Type == JTokenType.Float)
                ? (JToken)parameters.Min(parameter => parameter.ToObject<double>())
                : (JToken)parameters.Min(parameter => parameter.ToObject<long>());
        }

        #endregion

        #region Max

        /// <summary>
        /// Gets Max element.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken Max(string function, JToken[] parameters)
        {
            parameters = ExpressionBuiltInFunctions.UnwrapParameters(parameters);

            ExpressionBuiltInFunctions.ValidateParametersAtLeastOne(function, parameters);
            ExpressionBuiltInFunctions.ValidateAllParametersNumeric(function, parameters);

            return parameters.Any(parameter => parameter.Type == JTokenType.Float)
                ? (JToken)parameters.Max(parameter => parameter.ToObject<double>())
                : (JToken)parameters.Max(parameter => parameter.ToObject<long>());
        }

        #endregion

        #region Range

        /// <summary>
        /// Gets a sequence of numbers with specified range.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JArray Range(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            if (parameters[0].Type != JTokenType.Integer || parameters[1].Type != JTokenType.Integer)
            {
                throw new ExpressionException(
                    message: "Invalid parameter types for range function. Expected integers.");
            }

            var start = parameters[0].ToObject<int>();
            var count = parameters[1].ToObject<int>();

            if (count < 0 || count > 10000)
            {
                throw new ExpressionException(
                    message: "Range function parameters out of range.");
            }

            if ((long)start + (long)count - 1L > 2147483647L)
            {
                throw new ExpressionException(
                    message: "Range function parameters out of range.");
            }

            return new JArray(Enumerable.Range(start, count));
        }

        #endregion

        #region ConvertBase64ToJson

        /// <summary>
        /// Converts base64 to JSON.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The function parameters.</param>
        private static JToken ConvertBase64ToJson(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            if (!parameter.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects string parameter.");
            }

            try
            {
                var stringParameter = parameter.ToStringValue();

                var result = stringParameter.DecodeFromBase64String().TryFromJson<JToken>();
                return result ?? throw new ExpressionException(
                        message: $"Function '{function}' cannot parse JSON from base64.");
            }
            catch (FormatException ex)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' cannot decode base64 value.",
                    innerException: ex);
            }
        }

        #endregion

        #region ConvertBase64ToString

        /// <summary>
        /// Converts base64 to string using UTF8 encoding.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The function parameters.</param>
        private static JValue ConvertBase64ToString(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            if (!parameter.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects string parameter.");
            }

            try
            {
                var stringParameter = parameter.ToStringValue();

                return JValue.CreateString(stringParameter.DecodeFromBase64String());
            }
            catch (FormatException ex)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' cannot decode base64 value.",
                    innerException: ex);
            }
        }

        #endregion

        #region ConvertUriComponentToString

        /// <summary>
        /// Converts URI component to string using UTF8 encoding.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The function parameters.</param>
        private static JToken ConvertUriComponentToString(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            if (!parameter.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects string parameter.");
            }

            var stringParameter = parameter.ToStringValue();

            return HttpUtility.UrlDecode(stringParameter, Encoding.UTF8);
        }

        #endregion

        #region ConvertToUriComponent

        /// <summary>
        /// Converts to URI component.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The function parameters.</param>
        private static JToken ConvertToUriComponent(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            if (!parameter.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects string parameter.");
            }

            try
            {
                var stringParameter = parameter.ToStringValue()!;
                return Uri.EscapeDataString(stringParameter);
            }
            catch (Exception ex)
            {
                if (ex.IsFatal() || !(ex is FormatException || ex is ArgumentException))
                {
                    throw;
                }

                throw new ExpressionException(
                    message: $"Function '{function}' cannot convert value.",
                    innerException: ex);
            }
        }

        #endregion

        #region ConvertDataUriToString

        /// <summary>
        /// Converts data URI to string.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The function parameters.</param>
        private static JValue ConvertDataUriToString(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            if (!parameter.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' expects string parameter.");
            }

            var dataUri = parameter.ToObject<string>();
            if (!dataUri.StartsWithInsensitively(ExpressionBuiltInFunctions.DataUriSchemaPrefix))
            {
                throw new ExpressionException(
                    message: $"Function '{function}' received invalid data URI format.");
            }


            var dataSeperatorIndex = dataUri.IndexOf(',', StringComparison.Ordinal);
            if (dataSeperatorIndex < 0)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' received invalid data URI format.");
            }

            var data = dataUri[(dataSeperatorIndex + 1)..];
            var metadata = dataUri[ExpressionBuiltInFunctions.DataUriSchemaPrefix.Length..dataSeperatorIndex];
            var tokens = !string.IsNullOrEmpty(metadata) ? metadata.Split(';') : Array.Empty<string>();

            if (tokens.Any() && string.IsNullOrEmpty(tokens.First()) && (tokens.Count() != 2 || !tokens.Last().EqualsInsensitively("base64")))
            {
                throw new ExpressionException(
                    message: $"Function '{function}' received invalid data URI format.");
            }

            if (tokens.Skip(1).Any(token => string.IsNullOrWhiteSpace(token)))
            {
                throw new ExpressionException(
                    message: $"Function '{function}' received invalid data URI format.");
            }

            var charset = tokens.Length > 1 && tokens[1].StartsWithInsensitively("charset=") ? tokens[1]["charset=".Length..] : null;

            if (charset?.EqualsInsensitively("utf-8") == false)
            {
                throw new ExpressionException(
                    message: $"Function '{function}' received unsupported charset: {charset}.");
            }

            try
            {
                return JValue.CreateString(Encoding.UTF8.GetString(tokens.LastOrDefault().EqualsInsensitively("base64")
                    ? Convert.FromBase64String(data)
                    : HttpUtility.UrlDecodeToBytes(data)));
            }
            catch (Exception ex)
            {
                if (ex.IsFatal() || !(ex is FormatException || ex is ArgumentException))
                {
                    throw;
                }

                throw new ExpressionException(
                    message: $"Function '{function}' cannot convert value.",
                    innerException: ex);
            }
        }

        #endregion

        #region ConvertToDataUri

        /// <summary>
        /// Converts to data URI.
        /// </summary>
        /// <param name="function">The function name.</param>
        /// <param name="parameters">The function parameters.</param>
        private static JValue ConvertToDataUri(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            try
            {
                string data = null;
                if (parameter.Type is JTokenType.Object or JTokenType.Array)
                {
                    data = parameter.ToJson();
                }
                else
                {
                    data = parameter.ToObject<string>();
                }

                return ExpressionBuiltInFunctions.CreateDataUri(
                    contentType: parameter.IsTextBasedJTokenType() ? "text/plain;charset=utf8" : "application/json;charset=utf8",
                    content: data.EncodeToBase64String());
            }
            catch (Exception ex)
            {
                if (ex.IsFatal() || !(ex is FormatException || ex is ArgumentException))
                {
                    throw;
                }

                throw new ExpressionException(
                    message: $"Function '{function}' cannot convert value.",
                    innerException: ex);
            }
        }

        #endregion

        #region ConvertToArray

        /// <summary>
        /// Converts to array.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ConvertToArray(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            return parameter.Type != JTokenType.Array ? new JArray(parameter) : parameter;
        }

        #endregion

        #region CreateArray

        /// <summary>
        /// Creates an array from the parameters.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        private static JArray CreateArray(JToken[] parameters)
        {
            return new JArray(parameters);
        }

        #endregion

        #region CoalesceParameters

        /// <summary>
        /// Coalesces the parameters.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken CoalesceParameters(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParametersAtLeastOne(function, parameters);

            return Array.Find(parameters, parameter => parameter != null && parameter.Type != JTokenType.Null) ?? JValue.CreateNull();
        }

        #endregion

        #region ConvertToFloat

        /// <summary>
        /// Converts parameter to float.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ConvertToFloat(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            try
            {
                return parameters.Single().ToObject<double>();
            }
            catch (Exception ex)
            {
                if (ex.IsFatal() || !(ex is FormatException || ex is ArgumentException))
                {
                    throw;
                }

                throw new ExpressionException(
                    message: $"Function '{function}' cannot convert value.",
                    innerException: ex);
            }
        }

        #endregion

        #region ConvertToBool

        /// <summary>
        /// Converts parameter to boolean.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ConvertToBool(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            try
            {
                return parameters.Single().ToObject<bool>();
            }
            catch (Exception ex)
            {
                if (ex.IsFatal() || !(ex is FormatException || ex is ArgumentException))
                {
                    throw;
                }

                throw new ExpressionException(
                    message: $"Function '{function}' cannot convert value.",
                    innerException: ex);
            }
        }

        #endregion

        #region ComparisonLess

        /// <summary>
        /// Gets value of comparison 'less' operation.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ComparisonLess(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            var parameter1 = parameters[0];
            var parameter2 = parameters[1];

            if (parameter1.IsTextBasedJTokenType() || parameter2.IsTextBasedJTokenType())
            {
                if (!parameter1.IsTextBasedJTokenType() || !parameter2.IsTextBasedJTokenType())
                {
                    throw new ExpressionException(
                        message: $"Function '{function}' received incompatible parameter types for comparison.");
                }

                return string.Compare(parameter1.ToObject<string>().CoalesceString(), parameter2.ToObject<string>().CoalesceString(), StringComparison.InvariantCulture) < 0;
            }
            else
            {
                ExpressionBuiltInFunctions.ValidateAllParametersNumeric(function, parameters);

                return parameter1.Type == JTokenType.Float || parameter2.Type == JTokenType.Float
                    ? parameter1.ToObject<double>() < parameter2.ToObject<double>()
                    : parameter1.ToObject<long>() < parameter2.ToObject<long>();
            }
        }

        #endregion

        #region ComparisonLessOrEquals

        /// <summary>
        /// Gets value of comparison 'lessOrEquals' operation.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ComparisonLessOrEquals(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            var parameter1 = parameters[0];
            var parameter2 = parameters[1];

            if (parameter1.IsTextBasedJTokenType() || parameter2.IsTextBasedJTokenType())
            {
                if (!parameter1.IsTextBasedJTokenType() || !parameter2.IsTextBasedJTokenType())
                {
                    throw new ExpressionException(
                        message: $"Function '{function}' received incompatible parameter types for comparison.");
                }

                return string.Compare(parameter1.ToObject<string>().CoalesceString(), parameter2.ToObject<string>().CoalesceString(), StringComparison.InvariantCulture) <= 0;
            }
            else
            {
                ExpressionBuiltInFunctions.ValidateAllParametersNumeric(function, parameters);

                return parameter1.Type == JTokenType.Float || parameter2.Type == JTokenType.Float
                    ? parameter1.ToObject<double>() <= parameter2.ToObject<double>()
                    : parameter1.ToObject<long>() <= parameter2.ToObject<long>();
            }
        }

        #endregion

        #region ComparisonGreater

        /// <summary>
        /// Gets value of comparison 'greater' operation.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ComparisonGreater(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            var parameter1 = parameters[0];
            var parameter2 = parameters[1];

            if (parameter1.IsTextBasedJTokenType() || parameter2.IsTextBasedJTokenType())
            {
                if (!parameter1.IsTextBasedJTokenType() || !parameter2.IsTextBasedJTokenType())
                {
                    throw new ExpressionException(
                        message: $"Function '{function}' received incompatible parameter types for comparison.");
                }

                return string.Compare(parameter1.ToObject<string>().CoalesceString(), parameter2.ToObject<string>().CoalesceString(), StringComparison.InvariantCulture) > 0;
            }
            else
            {
                ExpressionBuiltInFunctions.ValidateAllParametersNumeric(function, parameters);

                return parameter1.Type == JTokenType.Float || parameter2.Type == JTokenType.Float
                    ? parameter1.ToObject<double>() > parameter2.ToObject<double>()
                    : parameter1.ToObject<long>() > parameter2.ToObject<long>();
            }
        }

        #endregion

        #region ComparisonGreaterOrEquals

        /// <summary>
        /// Gets value of comparison 'greaterOrEquals' operation.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ComparisonGreaterOrEquals(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            var parameter1 = parameters[0];
            var parameter2 = parameters[1];

            if (parameter1.IsTextBasedJTokenType() || parameter2.IsTextBasedJTokenType())
            {
                if (!parameter1.IsTextBasedJTokenType() || !parameter2.IsTextBasedJTokenType())
                {
                    throw new ExpressionException(
                        message: $"Function '{function}' received incompatible parameter types for comparison.");
                }

                return string.Compare(parameter1.ToObject<string>().CoalesceString(), parameter2.ToObject<string>().CoalesceString(), StringComparison.InvariantCulture) >= 0;
            }
            else
            {
                ExpressionBuiltInFunctions.ValidateAllParametersNumeric(function, parameters);

                return parameter1.Type == JTokenType.Float || parameter2.Type == JTokenType.Float
                    ? parameter1.ToObject<double>() >= parameter2.ToObject<double>()
                    : parameter1.ToObject<long>() >= parameter2.ToObject<long>();
            }
        }

        #endregion

        #region ComparisonEquals

        /// <summary>
        /// Gets value of comparison 'equals' operation.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ComparisonEquals(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            if (parameters.All(parameter => parameter.Type == JTokenType.Integer || parameter.Type == JTokenType.Float))
            {
                return parameters.Any(parameter => parameter.Type == JTokenType.Float)
                    ? parameters[0].ToObject<double>() == parameters[1].ToObject<double>()
                    : parameters[0].ToObject<long>() == parameters[1].ToObject<long>();
            }

            return JToken.DeepEquals(parameters[0], parameters[1]);
        }

        #endregion

        #region ConvertToJson

        /// <summary>
        /// Converts parameter to JSON.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken ConvertToJson(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            if (!parameter.IsTextBasedJTokenType())
            {
                throw new ExpressionException(
                    message: "Invalid parameter type for json function. Expected string.");
            }

            if (parameter.Type == JTokenType.Null)
            {
                return new JObject();
            }

            var stringParameter = parameter.ToStringValue();

            var result = stringParameter.TryFromJson<JToken>();
            return result ?? throw new ExpressionException(
                    message: "Invalid JSON string.");
        }

        #endregion

        #region LogicalNot

        /// <summary>
        /// Gets value of logical 'not' operation.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken LogicalNot(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 1);

            var parameter = parameters.Single();
            if (parameter.Type != JTokenType.Boolean)
            {
                throw new ExpressionException(
                    message: "Invalid parameter type for not function. Expected boolean.");
            }

            return !parameter.ToObject<bool>();
        }

        #endregion

        #region LogicalAnd

        /// <summary>
        /// Gets value of logical 'and' operation.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken LogicalAnd(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParametersAtLeastTwo(function, parameters);
            ExpressionBuiltInFunctions.ValidateAllParametersBoolean(function, parameters);

            return parameters.All(parameter => parameter.ToObject<bool>());
        }

        #endregion

        #region LogicalOr

        /// <summary>
        /// Gets value of logical 'or' operation.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken LogicalOr(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParametersAtLeastTwo(function, parameters);
            ExpressionBuiltInFunctions.ValidateAllParametersBoolean(function, parameters);

            return parameters.Any(parameter => parameter.ToObject<bool>());
        }

        #endregion

        #region If

        /// <summary>
        /// Returns one value if a condition is true and another value if it's false.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken If(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 3);

            var conditionParameter = parameters[0];
            if (conditionParameter.Type != JTokenType.Boolean)
            {
                throw new ExpressionException(
                    message: "Invalid condition parameter type for if function. Expected boolean.");
            }

            return conditionParameter.ToObject<bool>() ? parameters[1] : parameters[2];
        }

        #endregion

        #region True

        /// <summary>
        /// Always returns true.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JValue True(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 0);
            return new JValue(true);
        }

        #endregion

        #region False

        /// <summary>
        /// Always returns false.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JValue False(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 0);
            return new JValue(false);
        }

        #endregion

        #region Null

        /// <summary>
        /// Always returns null.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JValue Null(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 0);
            return JValue.CreateNull();
        }

        #endregion

        #region CreateObject

        /// <summary>
        /// Creates an object out of specified key value pairs.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JObject CreateObject(string function, JToken[] parameters)
        {
            // local function
            bool IsPropertyNameParameter(int index)
            {
                return index % 2 == 0;
            }

            // Note(majastrz): The function accepts a set of key value pairs. Given that the template expressions don't support
            // any form of tuples, we accept the key and the value as separate paramaters. This means that we have to validate
            // that the user specified an even number of parameters, however.
            ExpressionBuiltInFunctions.ValidateEvenNumberOfParameters(function, parameters);

            // Note(majastrz): Find indices of parameters at position 0, 2, 4, ... that aren't strings
            var invalidIndices = parameters
                .Select((propertyName, index) => IsPropertyNameParameter(index) && !propertyName.IsTextBasedJTokenType() ? index : -1)
                .Where(index => index >= 0);

            if (invalidIndices.Any())
            {
                throw new ExpressionException(
                    message: "Invalid property name parameter types for createObject function.");
            }

            var propertyNames = parameters
                .Where((parameter, index) => IsPropertyNameParameter(index))
                .Select(propertyName => propertyName.Value<string>());

            var duplicateProperties = propertyNames
                .GroupBy(name => name)
                .Where(group => group.Count() > 1)
                .Select(group => group.Key);

            if (duplicateProperties.Any())
            {
                throw new ExpressionException(
                    message: $"Function '{function}' received duplicate property names.");
            }

            var propertyValues = parameters.Where((parameter, index) => !IsPropertyNameParameter(index));

            return new JObject(propertyNames.Zip(propertyValues, (name, value) => new JProperty(name!, value)));
        }

        #endregion

        #region Items

        /// <summary>
        /// Allow iterating over object keys and values by returning an array of elements, with key and value properties.
        /// </summary>
        /// <remarks>
        /// For an object of format:
        /// <code>{"keyA": "valA", "keyB", "valB"}</code>
        /// The return value will be:
        /// <code>[{"key": "keyA", "value": "valA"}, {"key": "keyB", "value": "valB"}]</code>
        /// </remarks>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JArray Items(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function: function, parameters: parameters, count: 1);

            if (parameters[0].Type != JTokenType.Object)
            {
                throw new ExpressionException(message: $"Function '{function}' expects object parameter.");
            }

            var objectParameter = parameters[0].Value<JObject>();

            var output = new JArray();
            foreach (var property in objectParameter.Properties().OrderByAscending(keySelector: prop => prop.Name, comparer: StringComparer.OrdinalIgnoreCase))
            {
                output.Add(new JObject
                {
                    ["key"] = property.Name,
                    ["value"] = property.Value,
                });
            }

            return output;
        }

        #endregion

        #region TryGet

        /// <summary>
        /// Attempt to dereference a property of an object or an element of an array. If the dereference would fail, return `null` instead.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        /// <remarks>
        /// For example:
        ///     "[tryGet(createObject('key', 'value'), 'key')]"
        /// Would return:
        ///     'value'
        /// And:
        ///     "[tryGet(createArray('element'), 0)]"
        /// Would return:
        ///     'element'
        ///
        /// All of the following would return `null` (and would cause a deployment failure if attempted via standard property access):
        ///     "[tryGet(createObject(), 'property')]"
        ///     "[tryGet(createObject(), 0)]"
        ///     "[tryGet(null(), 'property')]"
        ///     "[tryGet('string', 'property')]"
        ///     "[tryGet(10, 'property')]"
        ///     "[tryGet(createArray(), 0)]"
        ///
        /// It is generally unsafe to dereference properties from the return value of `tryGet` (the function may return null and will not short-circuit an expression),
        /// so `tryGet` will accept zero or more additional parameters as properties to dereference should the initial safe dereference succeed.
        ///
        /// For example:
        ///     "[tryGet(createObject('key', createObject('nestedKey', 'value')), 'key', 'nestedKey')]"
        /// Would return:
        ///     'value'
        /// And:
        ///     "[tryGet(createObject('key', createObject('nestedKey', 'value')), 'unknownKey', 'nestedKey')]"
        /// Would return:
        ///     null
        /// And:
        ///     "[tryGet(createObject('key', createObject('nestedKey', 'value')), 'key', 'unknownNestedKey')]"
        /// Would raise an error, as <code>{nestedKey: 'value'}</code> has no property named 'unknownNestedKey'
        /// </remarks>
        private static JToken TryGet(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParametersAtLeastTwo(function: function, parameters: parameters);

            ExpressionBuiltInFunctions.ValidateIndexedParameterMultipleAllowedTypes(
                function: function,
                parameter: parameters[1],
                index: 1,
                allowedTypes: ExpressionBuiltInFunctions.TryGetAllowedArgumentTypes
            );

            return ExpressionBuiltInFunctions.PerformChainedDereferences(
                function: function,
                root: ExpressionBuiltInFunctions.PerformSafeDereference(root: parameters[0], property: parameters[1]),
                parameters: parameters);
        }

        #endregion

        #region AddDays

        /// <summary>
        /// Adds the specified number of days to a given date.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The date and the number of days to add to that date.</param>
        private static JToken AddDays(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);
            var dateParameter = ExpressionBuiltInFunctions.ValidateAndParseDateParameter(parameters[0]);
            var numberOfDays = ExpressionBuiltInFunctions.ValidateAndParseIntegerParameter(parameters[1]);

            try
            {
                return dateParameter.AddDays(numberOfDays).ToRoundtripFormatString();
            }
            catch (ArgumentOutOfRangeException)
            {
                throw new ExpressionException($"Overflow detected when adding {numberOfDays} days to date {dateParameter.ToRoundtripFormatString()}.");
            }
        }

        #endregion

        #region UtcNow

        /// <summary>
        /// Gets the current date and time in ISO 8601 date format <c>yyyy-MM-ddTHH:mm:ss.fffffffZ</c>
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The parameters.</param>
        private static JToken UtcNow(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 0);
            return DateTimeExtensions.PreciseUtcNow.ToRoundtripFormatString();
        }

        #endregion

        #region IpRangeContains

        /// <summary>
        /// Whether a range of IP addresses contains another range.
        /// </summary>
        /// <param name="function">The function.</param>
        /// <param name="parameters">The function arguments.</param>
        private static JToken IpRangeContains(string function, JToken[] parameters)
        {
            ExpressionBuiltInFunctions.ValidateParameterCount(function, parameters, 2);

            if (parameters[0].Type == JTokenType.String &&
                    parameters[1].Type == JTokenType.String &&
                    IPRange.TryParse(range: parameters[0].ToStringValue(), out var range) &&
                    IPRange.TryParse(range: parameters[1].ToStringValue(), out var targetRange))
            {
                return range.Contains(targetRange);
            }

            throw new ExpressionException($"IP range parameters are invalid.");
        }

        #endregion
    }

#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.

}
