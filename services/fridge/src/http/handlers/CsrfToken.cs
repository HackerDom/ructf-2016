using System.Net;
using System.Security.Cryptography;

using frɪdʒ.utils;

namespace frɪdʒ.http.handlers
{
	internal static class CsrfToken
	{
		public static void SetCsrfTokenCookie(this HttpListenerContext context)
		{
			if(context.Request.Cookies[CookieName] == null)
				context.SetCookie(CookieName, GenerateCsrfToken());
		}

		public static bool CheckCsrfToken(this HttpListenerContext context, string token)
		{
			return token != null && SecurityUtils.TimingSecureEquals(token, context.Request.Cookies[CookieName]?.Value);
		}

		private static string GenerateCsrfToken()
		{
			var bytes = new byte[16];
			using(var rng = new RNGCryptoServiceProvider())
				rng.GetBytes(bytes);
			return bytes.ToHex();
		}

		private const string CookieName = "csrf-token";
	}
}