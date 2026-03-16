namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Expressions
{
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// The count expression scope type.
    /// </summary>
    public enum CountScopeType
    {
        /// <summary>
        /// Field count expression scope.
        /// </summary>
        Field,

        /// <summary>
        /// Value count expression scope.
        /// </summary>
        Value
    }

    /// <summary>
    /// Count expression scope.
    /// </summary>
    public class CountExpressionScope
    {
        /// <summary>
        /// The default value count scope identifier.
        /// </summary>
        public const string DefaultValueCountScopeIdentifier = "default";

        /// <summary>
        /// The scope type.
        /// </summary>
        public CountScopeType Type { get; }

        /// <summary>
        /// The scope identifier.
        /// </summary>
        public string Identifier { get; }

        /// <summary>
        /// Creates a field count expression scope.
        /// </summary>
        /// <param name="identifier">The scope identifier (the alias of the array field).</param>
        public static CountExpressionScope FieldScope(string identifier)
        {
            return new CountExpressionScope(CountScopeType.Field, identifier);
        }

        /// <summary>
        /// Creates a value count expression scope.
        /// </summary>
        /// <param name="identifier">The scope identifier (the value specified in the value count expression 'name' property).</param>
        public static CountExpressionScope ValueScope(string identifier)
        {
            return new CountExpressionScope(CountScopeType.Value, identifier);
        }

        /// <summary>
        /// Creates a default value count expression scope (for value count expressions without a 'name' property).
        /// </summary>
        public static CountExpressionScope DefaultValueScope()
        {
            return new CountExpressionScope(CountScopeType.Value, CountExpressionScope.DefaultValueCountScopeIdentifier);
        }

        /// <summary>
        /// Whether this is a field count scope and the field alias is a parent of the provided alias.
        /// </summary>
        /// <param name="aliasName">The other alias name.</param>
        public bool IsParentFieldCountScopeOf(string aliasName)
        {
            return this.Type == CountScopeType.Field && aliasName.StartsWithOrdinalInsensitively(this.Identifier);
        }

        /// <summary>
        /// Whether this is a value count scope and its identifier is the same as the provided identifier.
        /// </summary>
        /// <param name="identifier">The identifier of the other scope.</param>
        public bool IsValueCountScopeMatching(string identifier)
        {
            return this.Type == CountScopeType.Value && identifier.EqualsOrdinalInsensitively(this.Identifier);
        }


        private CountExpressionScope(CountScopeType scopeType, string identifier)
        {
            this.Type = scopeType;
            this.Identifier = identifier;
        }
    }

    /// <summary>
    /// Extensions for stacks of <see cref="CountExpressionScope"/>.
    /// </summary>
    public static class CountExpressionScopeStackExtensions
    {
        /// <summary>
        /// Get the scope that is referred by, or a parent of, a field accessed via a field() function. Start looking from the top of the stack.
        /// </summary>
        /// <remarks>The returned value can be null, since field functions can refer fields that are outside of the count expression scope.</remarks>
        /// <param name="field">The field name provided as an argument to the field() function.</param>
        /// <param name="scopes">The scopes.</param>
        public static CountExpressionScope? ResolveFieldFunctionReference(this Stack<CountExpressionScope> scopes, string field)
        {
            return scopes.FirstOrDefault(scope => scope.IsParentFieldCountScopeOf(aliasName: field));
        }

        /// <summary>
        /// Get the scope that is referred by a current() function. Fail if no reference was found.
        /// </summary>
        /// <param name="identifier">The identifier of provided as an argument to the current() function.</param>
        /// <param name="scopes">The scopes.</param>
        public static CountExpressionScope? ResolveCurrentFunctionReference(this Stack<CountExpressionScope> scopes, string? identifier)
        {
            if (identifier == null)
            {
                if (scopes.Count == 1)
                {
                    return scopes.First();
                }

                return null;
            }

            return scopes.FirstOrDefault(scope => scope.IsParentFieldCountScopeOf(aliasName: identifier) || scope.IsValueCountScopeMatching(identifier: identifier));
        }

        /// <summary>
        /// Try getting the scope that is referred by a current() function.
        /// </summary>
        /// <param name="identifier">The identifier of provided as an argument to the current() function.</param>
        /// <param name="countExpressionScope">The resolved count expression scope.</param>
        /// <param name="scopes">The scopes.</param>
        public static bool TryResolveCurrentFunctionReference(this Stack<CountExpressionScope> scopes, string identifier, out CountExpressionScope? countExpressionScope)
        {
            countExpressionScope = null;
            if (scopes.Count != 0)
            {
                return false;
            }

            if (identifier == null)
            {
                if (scopes.Count == 1)
                {
                    countExpressionScope = scopes.First();
                    return true;
                }

                return false;
            }

            var scope = scopes.FirstOrDefault(
                   scope => scope.IsParentFieldCountScopeOf(aliasName: identifier)
                || scope.IsValueCountScopeMatching(identifier: identifier));

            if (scope != null)
            {
                countExpressionScope = scope;
                return true;
            }

            return false;
        }
    }
}
