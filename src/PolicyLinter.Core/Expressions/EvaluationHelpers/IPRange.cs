// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions.EvaluationHelpers
{
    using System;
    using System.Net;
    using System.Net.Sockets;

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.

    /// <summary>
    /// Represents a range of IPv4 or IPv6 addresses
    /// </summary>
    /// <remarks>
    /// Ported from Azure Policy engine implementation.
    /// </remarks>
    public class IPRange
    {
        /// <summary>
        /// The start address bytes.
        /// </summary>
        private byte[] StartAddress { get; set; }
        /// <summary>
        /// The end address bytes.
        /// </summary>
        private byte[] EndAddress { get; set; }

        /// <summary>
        /// Whether this range contains the other range. For different address families this will always return false.
        /// </summary>
        /// <param name="other">The other range.</param>
        public bool Contains(IPRange other)
        {
            return
                this.StartAddress.Length == other.StartAddress.Length &&
                this.EndAddress.Length == other.EndAddress.Length &&
                IPRange.GreaterOrEquals(other.StartAddress, this.StartAddress) &&
                IPRange.LessOrEquals(other.EndAddress, this.EndAddress);
        }

        /// <summary>
        /// Try parse the given range.
        /// </summary>
        /// <param name="range">The range in string format.</param>
        /// <param name="ipRange">The result.</param>
        public static bool TryParse(string? range, out IPRange ipRange)
        {
            if (string.IsNullOrEmpty(range))
            {
                ipRange = null;
                return false;
            }

            var rangeSeperatorInd = range.IndexOf('-', StringComparison.Ordinal);
            if (rangeSeperatorInd != -1)
            {
                return IPRange.TryParseFromStartAndEndAddresses(
                    start: range.Substring(0, rangeSeperatorInd),
                    end: range.Substring(rangeSeperatorInd + 1),
                    ipRange: out ipRange);
            }
            else
            {
                return IPRange.TryParseFromCidrOrIpAddress(range: range, ipRange: out ipRange);
            }
        }

        #region Parse helpers

        /// <summary>
        /// Try parsing the given range provided in a form of start and end addresses.
        /// </summary>
        /// <param name="start">The start address.</param>
        /// <param name="end">The end address.</param>
        /// <param name="ipRange">The result.</param>
        private static bool TryParseFromStartAndEndAddresses(string start, string end, out IPRange ipRange)
        {
            ipRange = null;
            if (IPAddress.TryParse(start, out var startAddress) &&
                IPAddress.TryParse(end, out var endAddress) &&
                startAddress.AddressFamily == endAddress.AddressFamily)
            {
                var startAddressBytes = startAddress.GetAddressBytes();
                var endAddressBytes = endAddress.GetAddressBytes();

                // Don't allow ranges that don't include any address
                if (IPRange.GreaterOrEquals(endAddressBytes, startAddressBytes))
                {
                    ipRange = new IPRange()
                    {
                        StartAddress = startAddressBytes,
                        EndAddress = endAddressBytes
                    };

                    return true;
                }

                return false;
            }

            return false;
        }

        /// <summary>
        /// Try parsing the given range provided in a form of a CIDR subnet or as a single IP address.
        /// </summary>
        /// <param name="range">The range.</param>
        /// <param name="ipRange">The result.</param>
        private static bool TryParseFromCidrOrIpAddress(string range, out IPRange ipRange)
        {
            ipRange = null;

            // Expect one or less subnets
            var parts = range.Split('/');
            if (parts.Length is not 1 and not 2)
            {
                return false;
            }

            if (IPAddress.TryParse(parts[0], out var prefix) &&
                (prefix.AddressFamily == AddressFamily.InterNetwork || prefix.AddressFamily == AddressFamily.InterNetworkV6))
            {
                // Try parse the mask if it is provided, default to the full mask if it doesn't
                int mask;
                if (parts.Length == 2)
                {
                    if (!int.TryParse(parts[1], out mask))
                    {
                        return false;
                    }

                    if (mask < 0 || mask > IPRange.GetMaxMask(prefix.AddressFamily))
                    {
                        return false;
                    }
                }
                else
                {
                    mask = IPRange.GetMaxMask(prefix.AddressFamily);
                }

                var prefixBytes = prefix.GetAddressBytes();

                // Create the start and end address by filling the bits outside the mask with zeros and ones respectively.
                ipRange = new IPRange
                {
                    StartAddress = IPRange.ApplyMaskAndFill(prefixBytes, mask, 0x00),
                    EndAddress = IPRange.ApplyMaskAndFill(prefixBytes, mask, 0xff)
                };

                return true;
            }

            return false;
        }

        /// <summary>
        /// Get the max mask for the given IP address family.
        /// </summary>
        /// <param name="addressFamily">The address family</param>
        private static int GetMaxMask(AddressFamily addressFamily)
        {
            return addressFamily == AddressFamily.InterNetwork ? 32 : 128;
        }

        /// <summary>
        /// Creates new byte array filled with the masked bits of the prefix + the given fill for everything else. This is used for creating the min\max address of a CIDR range.
        /// </summary>
        /// <param name="prefix">The address prefix.</param>
        /// <param name="mask">The mask.</param>
        /// <param name="fill">The value to fill.</param>
        private static byte[] ApplyMaskAndFill(byte[] prefix, int mask, byte fill)
        {
            var result = new byte[prefix.Length];
            var currentByte = 0;

            // If the mask is greater than 8, we have bytes that can be copied as-is from the prefix to the result
            var numOfFullMaskBytes = mask / 8;
            while (currentByte < prefix.Length && currentByte < numOfFullMaskBytes)
            {
                result[currentByte] = prefix[currentByte];
                currentByte++;
            }

            // The next byte may be partially masked, handle that.
            if (currentByte < prefix.Length)
            {
                var maskedBits = mask % 8;

                // Copy the masked bits to the result, put 0 in the unmasked bits.
                result[currentByte] = (byte)(prefix[currentByte] & (byte)~(0xff >> maskedBits));

                // Fill the unmasked bits (don't bother if the fill is 0x00)
                if (fill != 0x00)
                {
                    result[currentByte] |= (byte)(fill >> maskedBits);
                }
            }

            // Fill the rest of the bytes (don't bother if the fill is 0x00)
            currentByte++;
            while (fill != 0x00 && currentByte < prefix.Length)
            {
                result[currentByte] |= fill;
                currentByte++;
            }

            return result;
        }

        #endregion

        #region Compare Helpers

        /// <summary>
        /// Find the index of the first byte that is different in the given addresses. Returns the array length if 2 addresses are equal.
        /// </summary>
        /// <param name="address1">The first address.</param>
        /// <param name="address2">The second address.</param>
        private static int FindIndexOfFirstDifferentByte(byte[] address1, byte[] address2)
        {
            var firstDiffIndex = 0;
            while (firstDiffIndex < address1.Length &&
                firstDiffIndex < address2.Length &&
                address1[firstDiffIndex] == address2[firstDiffIndex])
            {
                firstDiffIndex++;
            }

            return firstDiffIndex;
        }

        /// <summary>
        /// Whether the first address is greater or equals to the second address.
        /// </summary>
        /// <param name="address1">The first address.</param>
        /// <param name="address2">The second address.</param>
        private static bool GreaterOrEquals(byte[] address1, byte[] address2)
        {
            int firstDiffIndex = IPRange.FindIndexOfFirstDifferentByte(address1, address2);
            return firstDiffIndex == address1.Length || address1[firstDiffIndex] > address2[firstDiffIndex];
        }

        /// <summary>
        /// Whether the first address is less or equals to the second address.
        /// </summary>
        /// <param name="address1">The first address.</param>
        /// <param name="address2">The second address.</param>
        private static bool LessOrEquals(byte[] address1, byte[] address2)
        {
            int firstDiffIndex = IPRange.FindIndexOfFirstDifferentByte(address1, address2);
            return firstDiffIndex == address1.Length || address1[firstDiffIndex] < address2[firstDiffIndex];
        }

        #endregion
    }

#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
}
