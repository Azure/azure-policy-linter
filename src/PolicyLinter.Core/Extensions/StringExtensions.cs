namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Extensions
{
    /// <summary>
    /// String extensions.
    /// </summary>
    internal static class StringExtensions
    {
        /// <summary>
        /// Opportunistically determines if the part count is larger than target
        /// Use this intead of .SplitRemoveEmpty().Length > target when the string list is not needed.
        /// </summary>
        /// <param name="value">the input string</param>
        /// <param name="separator">the character to split with</param>
        /// <param name="target">the target count</param>
        public static bool IsNonEmptySegmentCountLargerThanTarget(this string value, char separator, int target)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            var count = 0;
            var moveNext = false;

            // Trim beginning
            int i = 0;
            while (i < value.Length && value[i] == separator)
            {
                i++;
            }

            for (; i < value.Length && count < target; i++)
            {
                // Loop if we hit the same char consecutively
                if (moveNext && value[i] == separator)
                {
                    continue;
                }

                // Mark char found and move on
                if (value[i] == separator)
                {
                    moveNext = true;
                    continue;
                }

                // Different char - only increment count if we've seen it before.
                if (moveNext)
                {
                    count++;
                }

                moveNext = false;
            }

            return count >= target;
        }
    }
}
