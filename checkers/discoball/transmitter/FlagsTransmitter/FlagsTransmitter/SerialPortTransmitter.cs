using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Ports;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FlagsTransmitter.Utils;
using log4net;

namespace FlagsTransmitter
{
	class SerialPortTransmitter
	{
		public SerialPortTransmitter(FlagsContainer flagsContainer, string comPortName, int speedInBod, bool withParity)
		{
			this.flagsContainer = flagsContainer;
			comPort = new SerialPort(comPortName, speedInBod, withParity ? Parity.Even : Parity.None, 8, StopBits.One) { WriteBufferSize = 32 };
			comPort.Open();

			worker = new Thread(WorkerLoop);
		}

		void WorkerLoop()
		{
			while(true)
			{
                var flags = flagsContainer.EnumerateFlags().ToArray();
			    if(flags.Length == 0)
			    {
			        Thread.Sleep(1000);
                    continue;
			    }
                try
                {
                    var sw = Stopwatch.StartNew();
					foreach(var flag in flags)
					{
						TransmitFlag(flag);
					}
                    sw.Stop();
                    log.InfoFormat($"Transmitted batch of {flags.Length} flags in {sw.ElapsedMilliseconds}ms");
				}
				catch(Exception e)
				{
					log.Error("Some unexpected error in Transmitter worker loop. Sleeping and retrying", e);
					Thread.Sleep(1000);
				}
			}
		}

		private void TransmitFlag(KeyValuePair<string, string> kvp)
		{
		    string ip = kvp.Key;
		    string flag = kvp.Value;

		    var sw = Stopwatch.StartNew();
			var flagBytes = Encoding.GetEncoding(1251).GetBytes(flag);
			flagBytes = BitHelper.Encode5B4B(flagBytes);
			for(int i = 0; i < 8; i++)
			{
				comPort.Write(flagBytes, 0, flagBytes.Length);
				BitHelper.RotateLeft(flagBytes);
			}
            sw.Stop();
            log.InfoFormat($"Transmitted flag {flag} for team {ip} in {sw.ElapsedMilliseconds}ms");

        }

		public void Start()
		{
			worker.Start();
			log.Info("SerialPortTransmitter started");
		}

		private readonly FlagsContainer flagsContainer;
		private Thread worker;

		private SerialPort comPort;

		private static readonly ILog log = LogManager.GetLogger(typeof(SerialPortTransmitter));
	}
}
