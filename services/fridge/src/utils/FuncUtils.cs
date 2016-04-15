using System;

namespace frɪdʒ.utils
{
	internal static class FuncUtils
	{
		public static TOut TryOrDefault<TOut, TIn>(this Func<TIn, TOut> func, TIn input)
		{
			try { return func(input); } catch { return default(TOut); }
		}
	}
}