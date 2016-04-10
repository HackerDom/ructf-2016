using System;
using System.CodeDom;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Node.Messages;
using Node.Serialization;

namespace Node.Connections.LocalTcp
{
    internal class LocalTcpConnection : IConnection
    {
        public LocalTcpConnection(LocalTcpAddress address, Socket socket, IConnectionUtility connectionUtility)
        {
            RemoteAddress = address;
            this.socket = socket;
            stream = new NonblockingSocketStream(socket, connectionUtility);
            State = ConnectionState.Connecting;
        }

        public SendResult Send(IMessage message)
        {
            if (State != ConnectionState.Connected)
                return SendResult.Failure;
            return SendInternal(message);
        }

        public IMessage Receive()
        {
            if (State != ConnectionState.Connected)
                return null;
            return ReceiveInternal();
        }

        public void Tick(bool canRead)
        {
            if (State != ConnectionState.Connecting)
                return;

            if (!establishmentStage.HasFlag(EstablishmentStage.SentHello))
            {
                if (SendInternal(new HelloMessage()) == SendResult.Success)
                    establishmentStage |= EstablishmentStage.SentHello;
            }
            if (!establishmentStage.HasFlag(EstablishmentStage.ReceivedHello) && canRead)
            {
                var result = ReceiveInternal() as HelloMessage;
                if (result != null)
                    establishmentStage |= EstablishmentStage.ReceivedHello;
            }
            if (establishmentStage == EstablishmentStage.Established)
                State = ConnectionState.Connected;

            Console.WriteLine("!! conn -> {0} : {1}, {2}", RemoteAddress, establishmentStage, canRead);
        }

        public void Close()
        {
            socket.Close();
            State = ConnectionState.Closed;
        }

        public IAddress RemoteAddress { get; }

        public ConnectionState State { get; private set; }

        public Socket Socket => socket;

        private SendResult SendInternal(IMessage message)
        {
            try
            {
                return stream.TryWrite(message) ? SendResult.Success : SendResult.Partial;
            }
            catch (Exception e)
            {
                Console.WriteLine("Send : " + e.Message);
                socket.Close();
                State = ConnectionState.Failed;
                return SendResult.Failure;
            }
        }

        private IMessage ReceiveInternal()
        {
            try
            {
                IMessage message;
                return stream.TryRead(out message) ? message : null;
            }
            catch (Exception e)
            {
                Console.WriteLine("Receive : " + e.Message);
                socket.Close();
                State = ConnectionState.Failed;
                return null;
            }
        }

        private readonly Socket socket;
        private readonly NonblockingSocketStream stream;

        private EstablishmentStage establishmentStage;

        [Flags]
        private enum EstablishmentStage
        {
            SentHello = 1,
            ReceivedHello = 2,
            Established = 3
        }
    }
}