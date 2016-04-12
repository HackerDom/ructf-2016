using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
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

		public static IEnumerable<TKey> EnumerateKeys<TKey, TValue>(this IDictionary<TKey, TValue> source)
		{
			return source.Select(pair => pair.Key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static bool TryRemove<TKey, TValue>(this ConcurrentDictionary<TKey, TValue> source, TKey key)
		{
			TValue value;
			return source.TryRemove(key, out value);
		}
	}
}