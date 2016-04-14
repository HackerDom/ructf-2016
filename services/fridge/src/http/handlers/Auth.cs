using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;

using frɪdʒ.utils;

namespace frɪdʒ.http.handlers
{
	internal static class Auth
	{
		static Auth()
		{
			Key = new byte[KeyLength];
			using(var stream = new FileStream(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "key"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
			{
				if(stream.ReadToBuffer(Key) != KeyLength)
				{
					using(var rng = new RNGCryptoServiceProvider())
						rng.GetBytes(Key);
					stream.Write(Key, 0, KeyLength);
				}
			}
		}

		public static string GetAuth(this CookieCollection cookies)
		{
			var login = cookies[LoginCookieName]?.Value;
			var auth = cookies[AuthCookieName]?.Value;
			return login != null && SecurityUtils.TimingSecureEquals(auth, Hmac(login)) ? login : null;
		}

		public static void SetAuthCookies(this HttpListenerContext context, string login)
		{
			context.SetCookie(LoginCookieName, login);
			context.SetCookie(AuthCookieName, Hmac(login), true);
		}

		private static string Hmac(string value)
		{
			using(var hmac = new HMACSHA256(Key))
				return hmac.ComputeHash(value.ToBytes()).ToHex();
		}

		private const int KeyLength = 64;
		private const string LoginCookieName = "login";
		private const string AuthCookieName = "auth";
		private static readonly byte[] Key;
	}
}