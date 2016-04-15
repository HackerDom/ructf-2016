using System;
using System.Net;
using FlagsTransmitter;
using log4net;

namespace Electro.Handlers
{
	class AddFlagHandler : BaseHttpHandler
	{
		private readonly FlagsContainer flagsContainer;

		public AddFlagHandler(FlagsContainer flagsContainer, string prefix) : base(prefix)
		{
			this.flagsContainer = flagsContainer;
		}

		protected override void ProcessRequest(HttpListenerContext context)
		{
			context.Request.AssertMethod(WebRequestMethods.Http.Get);

			var id = context.Request.QueryString["id"];
			var ip = context.Request.QueryString["ip"];
			var flag = context.Request.QueryString["flag"];

			flagsContainer.SetFlag(ip, flag);

			log.Info($"Set new flag {flag} for id {id} on ip {ip}");
		}

		private static readonly ILog log = LogManager.GetLogger(typeof(AddFlagHandler));

	}
}
