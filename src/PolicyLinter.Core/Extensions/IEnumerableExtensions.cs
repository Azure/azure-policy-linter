namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Extensions
{
    using System;
    using System.Collections.Generic;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;

    /// <summary>
    /// Extensions for <see cref="IEnumerable{T}"/>.
    /// </summary>
    internal static class IEnumerableExtensions
    {
        /// <summary>
        /// Creates a Dictionary from an IEnumerable according to a specified key selector function and case insensitive comparer.
        /// </summary>
        /// <typeparam name="TSource">Type of the source enumerable.</typeparam>
        /// <typeparam name="TElement">Type of the dictionary element.</typeparam>
        /// <param name="source">The source collection.</param>
        /// <param name="keySelector">A function to extract key from each source element.</param>
        /// <param name="elementSelector">A function to extract element from each source element.</param>
        /// <param name="capacity">The capacity of the dictionary, if known.</param>
        public static OrdinalInsensitiveDictionary<TElement> ToOrdinalInsensitiveDictionary<TSource, TElement>(this IEnumerable<TSource> source, Func<TSource, string> keySelector, Func<TSource, TElement> elementSelector, int capacity = -1)
        {
            var dictionary = capacity > -1 ? new OrdinalInsensitiveDictionary<TElement>(capacity: capacity) : new OrdinalInsensitiveDictionary<TElement>();
            foreach (var current in source)
            {
                dictionary[keySelector(current)] = elementSelector(current);
            }

            return dictionary;
        }

    }
}
