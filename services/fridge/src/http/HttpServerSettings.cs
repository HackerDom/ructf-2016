using System;

namespace frɪdʒ.http
{
	internal static class HttpServerSettings
	{
		public static readonly int Concurrency = Math.Max(8, Environment.ProcessorCount);

		public const string ServerName = "fridge/1.0";

		public const int MaxRequestSize = 4096;
		public const int MaxResponseSize = 8192;

		public const int ReadWriteTimeout = 1000;
	}
}