using System;

namespace frɪdʒ.http
{
	internal static class HttpServerSettings
	{
		public static readonly int Concurrency = Math.Max(4, Environment.ProcessorCount - 2);

		public const string ServerName = "fridge/1.0";

		public const int MaxRequestSize = 4096;
		public const int MaxResponseSize = 8192;
	}
}