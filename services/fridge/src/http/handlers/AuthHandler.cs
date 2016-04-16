using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

using frɪdʒ.Db;
using frɪdʒ.utils;

using Newtonsoft.Json;

namespace frɪdʒ.http.handlers
{
	internal class AuthHandler
	{
		public AuthHandler(Func<string, Task> callback)
		{
			this.callback = callback;
		}

		public async Task SignInAsync(HttpListenerContext context)
		{
			var data = await CheckFormAsync(context);

			var login = data.GetOrDefault("login");
			var pass = data.GetOrDefault("pass");

			if(string.IsNullOrEmpty(login) || string.IsNullOrEmpty(pass))
				throw new HttpException(400, "Login/pass required");

			var user = Users.Find(login);
			if(user == null || !SecurityUtils.TimingSecureEquals(pass.Hmac(), user.Pass))
				throw new HttpException(403, "Invalid login/pass");

			context.SetAuthCookies(user.Login);
			await context.WriteStringAsync(JsonConvert.SerializeObject(new {login = user.Login, allergens = user.Allergens}));
		}

		public async Task SignUpAsync(HttpListenerContext context)
		{
			var data = await CheckFormAsync(context);

			var login = data.GetOrDefault("login");
			var pass = data.GetOrDefault("pass");

			if(string.IsNullOrEmpty(login) || string.IsNullOrEmpty(pass))
				throw new HttpException(400, "Login/pass required");

			if(login.Length < MinLength || pass.Length < MinLength)
				throw new HttpException(400, "Login/pass too short");

			if(login.Length > MaxLength || pass.Length > MaxLength)
				throw new HttpException(400, "Login/pass too long");

			var allergenString = data.GetOrDefault("allergen") ?? string.Empty;
			if(allergenString.Length > MaxAllergensSize)
				throw new HttpException(400, "Allergens too large");

			var allergens = allergenString.Split(AllergenDelim, StringSplitOptions.RemoveEmptyEntries);
			if(allergens.Length > MaxAllergens)
				throw new HttpException(400, "Too many allergens");

			if(!await Users.TryAdd(new User {Login = login, Pass = pass.Hmac(), Allergens = allergens}))
				throw new HttpException(409, "User already exists");

			context.SetAuthCookies(login);
			await callback(login).ConfigureAwait(false);
		}

		private async Task<Dictionary<string, string>> CheckFormAsync(HttpListenerContext context)
		{
			var data = await context.ReadPostDataAsync();
			if(data == null)
				throw new HttpException(400, "Login/pass required");

			if(!context.CheckCsrfToken(data.GetOrDefault("csrf-token")))
				throw new HttpException(403, "Request is forged");

			return data;
		}

		public static string FormatUserMessage(User user, string sender)
		{
			return JsonConvert.SerializeObject(new {type = "user", login = sender});
		}

		private const int MinLength = 4;
		private const int MaxLength = 20;
		private const int MaxAllergens = 3;
		private const int MaxAllergensSize = 128;
		private static readonly char[] AllergenDelim = {',', ' ', '\t', '\r', '\n', '\v'};
		private readonly Func<string, Task> callback;
	}
}