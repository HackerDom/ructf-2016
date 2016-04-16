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
		public FoodHandler(Func<string, Food, Task> callback)
		{
			this.callback = callback;
		}

		public async Task PutAsync(HttpListenerContext context)
		{
			var data = await context.ReadPostDataAsync();
			if(data == null)
				return;

			var title = data.GetOrDefault("title");
			var ingredients = data.GetOrDefault("ingredients");

			if(string.IsNullOrEmpty(title))
				throw new HttpException(400, "Food is invalid");

			if(!context.CheckCsrfToken(data.GetOrDefault("csrf-token")))
				throw new HttpException(403, "Request is forged");

			var food = await Foods.Add(title, ingredients);
			await context.WriteStringAsync(food.Id.ToString("N"));

			await callback(context.Request.Cookies.GetAuth() ?? "FoodBot", food).ConfigureAwait(false);
		}

		public async Task GetAsync(HttpListenerContext context)
		{
			Guid id;
			Food food;
			if(!Guid.TryParse(context.Request.QueryString["id"], out id) || (food = Foods.Find(id)) == null)
				throw new HttpException(404, "Food not found");

			await context.WriteStringAsync(JsonConvert.SerializeObject(new {title = food.Title, ingredients = food.Ingredients}));
		}

		public static string FormatUserMessage(User user, string sender, Food food)
		{
			return JsonConvert.SerializeObject(new {type = "food", login = sender, title = food.Title, allergens = user == null ? null : food.Ingredients.FindAll(user.Allergens)});
		}

		private readonly Func<string, Food, Task> callback;
	}
}