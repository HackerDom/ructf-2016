using System;
using System.Collections;
using System.Collections.Generic;
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
			var flags = flagsContainer.EnumerateFlagsInfinite();
			while(true)
			{
				try
				{
					foreach(var flag in flags)
					{
						TransmitFlag(flag);
					}
				}
				catch(Exception e)
				{
					log.Error("Some unexpected error in Transmitter worker loop. Sleeping and retrying", e);
					Thread.Sleep(1000);
				}
			}
		}

		private void TransmitFlag(string flag)
		{
			var flagBytes = Encoding.GetEncoding(1251).GetBytes(flag);
			flagBytes = BitHelper.Encode5B4B(flagBytes);
			for(int i = 0; i < 8; i++)
			{
				comPort.Write(flagBytes, 0, flagBytes.Length);
				BitHelper.RotateLeft(flagBytes);
			}
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
