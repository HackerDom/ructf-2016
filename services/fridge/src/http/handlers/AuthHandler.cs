using System;
using System.Net;
using System.Threading.Tasks;

using frɪdʒ.Db;
using frɪdʒ.utils;

namespace frɪdʒ.http.handlers
{
	internal class AuthHandler
	{
		public async Task AuthAsync(HttpListenerContext context)
		{
			var data = await context.ReadPostDataAsync();
			if(data == null)
				throw new HttpException(400, "Login/pass required");

			if(!context.CheckCsrfToken(data.GetOrDefault("csrf-token")))
				throw new HttpException(403, "Request is forged");

			var login = data.GetOrDefault("login");
			var pass = data.GetOrDefault("pass");

			if(string.IsNullOrEmpty(login) || string.IsNullOrEmpty(pass))
				throw new HttpException(400, "Login/pass required");

			if(login.Length < MinLength || pass.Length < MinLength)
				throw new HttpException(400, "Login/pass too short");

			if(login.Length > MaxLength || pass.Length > MaxLength)
				throw new HttpException(400, "Login/pass too long");

			var user = await Users.GetOrAdd(login, () => CreateNewUser(login, pass, data["allergen"]));
			if(pass != user.Pass)
				throw new HttpException(403, "Invalid login/pass");

			context.SetAuthCookies(user.Login);
		}

		private static User CreateNewUser(string login, string pass, string data)
		{
			var allergens = data.Split(AllergenDelim, StringSplitOptions.RemoveEmptyEntries);
			if(allergens.Length > 3)
				throw new HttpException(400, "Too many allergens");

			return new User {Login = login, Pass = pass, Allergens = allergens};
		}

		private const int MinLength = 4;
		private const int MaxLength = 32;
		private static readonly char[] AllergenDelim = {','};
	}
}