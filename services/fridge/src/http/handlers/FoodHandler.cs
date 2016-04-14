using System;
using System.Net;
using System.Threading.Tasks;

using frɪdʒ.Db;
using frɪdʒ.utils;
using Newtonsoft.Json;

namespace frɪdʒ.http.handlers
{
	internal class FoodHandler
	{
		public FoodHandler(Func<string, string, Task> callback)
		{
			this.callback = callback;
		}

		public async Task PutAsync(HttpListenerContext context)
		{
			var data = await context.ReadPostDataAsync();
			if(data == null)
				return;

			var food = data.GetOrDefault("food");
			if(string.IsNullOrEmpty(food))
				throw new HttpException(400, "Food is empty");

			if(!context.CheckCsrfToken(data.GetOrDefault("csrf-token")))
				throw new HttpException(403, "Request is forged");

			var id = await Foods.Add(food);
			await context.WriteStringAsync(id.ToString("N"));

			await callback(context.Request.Cookies.GetAuth() ?? "FoodBot", food).ConfigureAwait(false);
		}

		public async Task GetAsync(HttpListenerContext context)
		{
			Guid id;
			string data;
			if(!(Guid.TryParse(context.Request.QueryString["id"], out id) && (data = Foods.Find(id)) != null))
				throw new HttpException(404, "Food not found");

			await context.WriteStringAsync(data);
		}

		public static string FormatUserMessage(User user, string sender, string msg)
		{
			return JsonConvert.SerializeObject(new {login = sender, allergens = user == null ? null : msg.FindAll(user.Allergens)});
		}

		private readonly Func<string, string, Task> callback;
	}
}