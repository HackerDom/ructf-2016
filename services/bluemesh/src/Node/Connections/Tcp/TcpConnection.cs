using System;
using System.Net.Sockets;
using Node.Encryption;
using Node.Messages;

namespace Node.Connections.Tcp
{
    internal class TcpConnection : IConnection
    {
        public TcpConnection(TcpAddress localAddress, TcpAddress remoteAddress, Socket socket,  IConnectionUtility connectionUtility, IEncryptionManager encryptionManager)
        {
            RemoteAddress = remoteAddress;
            this.localAddress = localAddress;
            this.socket = socket;
            this.connectionUtility = connectionUtility;
            stream = new NonblockingSocketStream(socket, connectionUtility, encryptionManager.CreateEncoder(this));
            State = ConnectionState.Connecting;
        }

        public SendResult Send(IMessage message)
        {
            if (State != ConnectionState.Connected)
                return SendResult.Failure;
            return SendInternal(message);
        }

        public SendResult Send(byte[] rawData)
        {
            if (State != ConnectionState.Connected)
                return SendResult.Failure;
            return SendInternal(rawData);
        }

        public SendResult Push(IMessage message)
        {
            SendResult result;
            do
            {
                result = Send(message);
            } while (result == SendResult.Partial);
            return result;
        }

        public SendResult Push(byte[] rawData)
        {
            SendResult result;
            do
            {
                result = Send(rawData);
            } while (result == SendResult.Partial);
            return result;
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
                if (SendInternal(new StringMessage(localAddress.ToString())) == SendResult.Success)
                    establishmentStage |= EstablishmentStage.SentHello;
            }
            if (!establishmentStage.HasFlag(EstablishmentStage.ReceivedHello) && canRead)
            {
                var result = ReceiveInternal() as StringMessage;
                if (result != null)
                {
                    establishmentStage |= EstablishmentStage.ReceivedHello;
                    RemoteAddress = connectionUtility.ParseAddress(result.Text);
                }
            }
            if (establishmentStage == EstablishmentStage.Established)
            {
                if (ValidateConnection(this))
                    State = ConnectionState.Connected;
                else
                    Close();
                if (State != ConnectionState.Closed)
                    Console.WriteLine("Established connection : {0} <-> {1} ({2})", localAddress, RemoteAddress, GetHashCode());
                else
                    Console.WriteLine("Discarded connection : {0} <-> {1} ({2})", localAddress, RemoteAddress, GetHashCode());
            }

            //Console.WriteLine("!! conn -> {0} : {1}, {2}", RemoteAddress, establishmentStage, canRead);
        }

        public void Close()
        {
            socket.Close();
            State = ConnectionState.Closed;
        }

        public IAddress RemoteAddress { get; private set; }

        public IAddress LocalAddress => localAddress;

        public ConnectionState State { get; private set; }

        public Socket Socket => socket;

        public event Func<TcpConnection, bool> ValidateConnection = _ => true; 

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

        private SendResult SendInternal(byte[] rawData)
        {
            try
            {
                return stream.TryWrite(rawData) ? SendResult.Success : SendResult.Partial;
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

        private readonly TcpAddress localAddress;
        private readonly Socket socket;
        private readonly IConnectionUtility connectionUtility;
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