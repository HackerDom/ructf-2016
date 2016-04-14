using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

namespace frɪdʒ.utils
{
	internal static class StringUtils
	{
		/* NOTE: Vulnerability #2:
		 * In case of non-Ordinal string comparison it can be possible to find string, which doesn't really occur in source (in byte terms).
		 * Try it out: "abc".IndexOf(Encoding.UTF8.GetString(Enumerable.Repeat((byte)0xff, 100500).ToArray())) */
		public static string FindWord(this string value, string word)
		{
			if(value == null || word == null)
				return null;
			if(word == string.Empty)
				return null;
			var start = -1;
			while(++start <= value.Length && (start = value.IndexOf(word, start, StringComparison.InvariantCultureIgnoreCase)) >= 0)
			{
				if(start > 0 && !IsWordBoundary(value[start - 1]))
					continue;
				var end = start + word.Length;
				if(end >= value.Length || IsWordBoundary(value[end]))
					return value.Substring(start, end);
			}
			return null;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static bool IsWordBoundary(char chr)
		{
			return !char.IsLetterOrDigit(chr);
		}

		public static IEnumerable<string> FindAll(this string source, params string[] values)
		{
			return values?.Select(source.FindWord);
		}
	}
}