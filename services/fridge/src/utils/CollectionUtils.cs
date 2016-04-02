using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace frɪdʒ.utils
{
	internal static class CollectionUtils
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static TValue GetOrDefault<TKey, TValue>(this IDictionary<TKey, TValue> source, TKey key, TValue defaultValue = default(TValue))
		{
			TValue value;
			return key != null && source.TryGetValue(key, out value) ? value : defaultValue;
		}
	}
}