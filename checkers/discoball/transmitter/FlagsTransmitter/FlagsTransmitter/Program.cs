using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Electro.Handlers;

namespace FlagsTransmitter
{
	class Program
	{
		static void Main(string[] args)
		{
			if(args.Length < 1)
				PrintUsageAndExit();

			var comPortName = args[0];

			var flagsContainer = new FlagsContainer();
			var addFlagHandler = new AddFlagHandler(flagsContainer, "http://*:10000/addFlag/");
			addFlagHandler.Start();

			var transmitter = new SerialPortTransmitter(flagsContainer, comPortName, ComPortSpeed, false);
			transmitter.Start();

			new ManualResetEvent(false).WaitOne();
		}

		private static void PrintUsageAndExit()
		{
			Console.Error.WriteLine("Usage: program.exe <comPortName>");
			Environment.Exit(-1);
		}

		const int ComPortSpeed = 9600;

	}
}
