using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;

using frɪdʒ.utils;

namespace frɪdʒ.http
{
	internal class StaticHandler
	{
		public StaticHandler(string root)
		{
			this.root = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, root));
		}

		public async Task ProcessRequestAsync(HttpListenerContext context)
		{
			var fullpath = FindFile(context.Request.Url.LocalPath);
			if(fullpath == null)
				throw new HttpException(404, "Not Found");

			var contentType = ContentTypes.GetOrDefault(Path.GetExtension(fullpath));
			if(contentType == null)
				throw new HttpException(404, "Not Found");

			try
			{
				//NOTE: Mono breaks keep-alive connection on disponsing HttpResponseStream
				//using(var outputStream = context.Response.OutputStream)
				using(var stream = new FileStream(fullpath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan | FileOptions.Asynchronous))
				{
					context.Response.ContentLength64 = stream.Length;

					context.Response.ContentType = contentType;
					context.Response.AddHeader("Cache-Control", "private, max-age=" + MaxAge);
					context.Response.AddHeader("Accept-Ranges", "none");

					await stream.CopyToAsync(context.Response.OutputStream);
					await context.Response.OutputStream.FlushAsync();
				}
			}
			catch(FileNotFoundException)
			{
				throw new HttpException(404, "Not Found");
			}
		}

		private string FindFile(string relative)
		{
			var fullpath = Path.GetFullPath(Path.Combine(root, relative.TrimStart('/')));
			if(!fullpath.StartsWith(root, StringComparison.Ordinal))
				return null;

			if(fullpath.Length == root.Length)
				fullpath = Path.Combine(fullpath, DefaultDocument);

			return File.Exists(fullpath) ? fullpath : null;
		}

		private static readonly Dictionary<string, string> ContentTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
		{
			{".txt", "text/plain"},
			{".htm", "text/html"},
			{".html", "text/html"},
			{".css", "text/css"},
			{".js", "application/javascript"},
			{".ico", "image/x-icon"},
			{".gif", "image/gif"},
			{".png", "image/png"},
			{".jpg", "image/jpeg"},
			{".jpeg", "image/jpeg"}
		};

		private const string DefaultDocument = "index.html";

		private const int MaxAge = 300;

		private readonly string root;
	}
}