using System;
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

		public static Dictionary<TKey, TValue> ToDict<T, TKey, TValue>(this IEnumerable<T> source, Func<T, TKey> key, Func<T, TValue> val, IEqualityComparer<TKey> comparer = null)
		{
			var dict = new Dictionary<TKey, TValue>(comparer);
			foreach(var item in source)
				dict[key(item)] = val(item);
			return dict;
		}

		public static void ForEach<T>(this IEnumerable<T> source, Action<T> action)
		{
			foreach(var item in source)
				action(item);
		}
	}
}