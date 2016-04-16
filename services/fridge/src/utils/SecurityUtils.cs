using System.Runtime.CompilerServices;

namespace frɪdʒ.utils
{
	internal static class SecurityUtils
	{
		public static string ToHex(this byte[] bytes)
		{
			var array = new char[bytes.Length << 1];
			for(int i = 0; i < bytes.Length; i++)
			{
				var idx = i << 1;
				var b = (int)bytes[i];
				array[idx] = ToHex4Bit(b >> 4);
				array[idx + 1] = ToHex4Bit(b & 0xf);
			}
			return new string(array);
		}

		[MethodImpl(MethodImplOptions.NoOptimization)]
		public static bool TimingSecureEquals(string x, string y)
		{
			if(ReferenceEquals(x, y))
				return true;
			if(x == null || y == null || x.Length != y.Length)
				return false;
			int res = 0;
			for(int i = 0; i < x.Length; ++i)
				res |= x[i] ^ y[i];
			return res == 0;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static char ToHex4Bit(int b)
		{
			return (char)(b <= 9 ? b + Byte0 : b + ByteA - 10);
		}

		private const int Byte0 = '0';
		private const int ByteA = 'A';
	}
}