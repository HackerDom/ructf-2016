using System;
using System.CodeDom;
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
        }

        public SendResult Send(IMessage message)
        {
            if (State != ConnectionState.Connected)
                return SendResult.Failure;
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

        public IMessage Receive()
        {
            if (State != ConnectionState.Connected)
                return null;
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

        public void Close()
        {
            socket.Close();
            State = ConnectionState.Closed;
        }
        public IAddress RemoteAddress { get; }

        public ConnectionState State { get; private set; }

        public Socket Socket => socket;

        private readonly Socket socket;
        private readonly NonblockingSocketStream stream;
    }
}