using System;
using System.Collections.Generic;

namespace frɪdʒ.utils
{
	internal static class StringUtils
	{
		/* NOTE: Vulnerability #1 part #2:
		 * In case of non-Ordinal string comparison it can be possible to find string, which doesn't really occur in source (in byte terms).
		 * Try it out: "abc".IndexOf(Encoding.UTF8.GetString(Enumerable.Repeat((byte)0xff, 100500).ToArray())) */
		public static IEnumerable<string> FindAll(this string source, params string[] values)
		{
			foreach(var value in values)
			{
				var idx = source.IndexOf(value, StringComparison.InvariantCulture);
				if(idx >= 0)
					yield return source.Substring(idx, value.Length);
			}
		}
	}
}