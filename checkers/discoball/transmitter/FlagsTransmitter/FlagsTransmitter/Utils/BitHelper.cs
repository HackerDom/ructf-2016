using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlagsTransmitter.Utils
{
	class BitHelper
	{
		public static byte[] Encode5B4B(byte[] bytes)
		{
			if(bytes.Length % 4 != 0)
				throw new Exception("invalid array length, must be multiple of 4");

			string resultBits = "";
			var bitsString = string.Join("", bytes.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')));
			for(int i = 0; i < bitsString.Length; i+=4)
			{
				var bits = bitsString.Substring(i, 4);
				var bits5b = table[bits];
				resultBits += bits5b;
			}

			List<byte> result = new List<byte>();
			for(int i = 0; i < resultBits.Length; i += 8)
			{
				var bits = resultBits.Substring(i, 8);
				var b = Convert.ToByte(bits, 2);
				result.Add(b);
			}
			return result.ToArray();
		}

		private static Dictionary<string, string> table = new Dictionary<string, string>
		{
			{"0000", "11110"},
			{"0001", "01001"},
			{"0010", "10100"},
			{"0011", "10101"},
			{"0100", "01010"},
			{"0101", "01011"},
			{"0110", "01110"},
			{"0111", "01111"},
			{"1000", "10010"},
			{"1001", "10011"},
			{"1010", "10110"},
			{"1011", "10111"},
			{"1100", "11010"},
			{"1101", "11011"},
			{"1110", "11100"},
			{"1111", "11101"}
		};



		/// <summary>
		/// Rotates the bits in an array of bytes to the left.
		/// </summary>
		/// <param name="bytes">The byte array to rotate.</param>
		public static void RotateLeft(byte[] bytes)
		{
			bool carryFlag = ShiftLeft(bytes);

			if(carryFlag == true)
			{
				bytes[bytes.Length - 1] = (byte)(bytes[bytes.Length - 1] | 0x01);
			}
		}

		/// <summary>
		/// Rotates the bits in an array of bytes to the right.
		/// </summary>
		/// <param name="bytes">The byte array to rotate.</param>
		public static void RotateRight(byte[] bytes)
		{
			bool carryFlag = ShiftRight(bytes);

			if(carryFlag == true)
			{
				bytes[0] = (byte)(bytes[0] | 0x80);
			}
		}

		/// <summary>
		/// Shifts the bits in an array of bytes to the left.
		/// </summary>
		/// <param name="bytes">The byte array to shift.</param>
		public static bool ShiftLeft(byte[] bytes)
		{
			bool leftMostCarryFlag = false;

			// Iterate through the elements of the array from left to right.
			for(int index = 0; index < bytes.Length; index++)
			{
				// If the leftmost bit of the current byte is 1 then we have a carry.
				bool carryFlag = (bytes[index] & 0x80) > 0;

				if(index > 0)
				{
					if(carryFlag == true)
					{
						// Apply the carry to the rightmost bit of the current bytes neighbor to the left.
						bytes[index - 1] = (byte)(bytes[index - 1] | 0x01);
					}
				}
				else
				{
					leftMostCarryFlag = carryFlag;
				}

				bytes[index] = (byte)(bytes[index] << 1);
			}

			return leftMostCarryFlag;
		}

		/// <summary>
		/// Shifts the bits in an array of bytes to the right.
		/// </summary>
		/// <param name="bytes">The byte array to shift.</param>
		public static bool ShiftRight(byte[] bytes)
		{
			bool rightMostCarryFlag = false;
			int rightEnd = bytes.Length - 1;

			// Iterate through the elements of the array right to left.
			for(int index = rightEnd; index >= 0; index--)
			{
				// If the rightmost bit of the current byte is 1 then we have a carry.
				bool carryFlag = (bytes[index] & 0x01) > 0;

				if(index < rightEnd)
				{
					if(carryFlag == true)
					{
						// Apply the carry to the leftmost bit of the current bytes neighbor to the right.
						bytes[index + 1] = (byte)(bytes[index + 1] | 0x80);
					}
				}
				else
				{
					rightMostCarryFlag = carryFlag;
				}

				bytes[index] = (byte)(bytes[index] >> 1);
			}

			return rightMostCarryFlag;
		}
	}
}
