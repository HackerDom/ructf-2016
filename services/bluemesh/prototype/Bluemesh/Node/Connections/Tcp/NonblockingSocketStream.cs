using System;
using System.Net.Sockets;
using Node.Messages;

namespace Node.Connections.Tcp
{
    internal class NonblockingSocketStream
    {
        public NonblockingSocketStream(Socket socket, IConnectionUtility connectionUtility)
        {
            this.socket = socket;
            this.connectionUtility = connectionUtility;
        }

        public bool TryWrite(IMessage message)
        {
            if (writeLength < 0)
                writeLength = new MessageContainer(message).WriteToBuffer(writeBuffer, 0);
            var bytesSent = socket.SendSafe(writeBuffer, writePos, writeLength - writePos);
            writePos += bytesSent;
            if (writePos >= writeLength)
            {
                writeLength = -1;
                writePos = 0;
                return true;
            }
            return false;
        }

        public bool TryRead(out IMessage message)
        {
            message = null;
            if (readPos < MessageContainer.HeaderSize)
            {
                var bytesRead = socket.ReceiveSafe(readBuffer, readPos, MessageContainer.HeaderSize - readPos);
                readPos += bytesRead;
                //Console.WriteLine("TryRead : header : bytesRead = " + bytesRead);
                return false;
            }
            if (readLength < 0)
            {
                readLength = MessageContainer.GetNeededLength(readBuffer, 0);
            }
            if (readPos < readLength)
            {
                var bytesRead = socket.ReceiveSafe(readBuffer, readPos, readLength - readPos);
                readPos += bytesRead;
                //Console.WriteLine("TryRead : body : bytesRead = " + bytesRead);
            }
            if (readPos >= readLength)
            {
                readLength = -1;
                readPos = 0;
                message = MessageContainer.ReadFromBuffer(readBuffer, 0, connectionUtility).Message;
                //Console.WriteLine("TryRead : success : message = " + message);
                return true;
            }

            return false;
        }

        private int readPos;
        private int writePos;
        private int readLength = -1;
        private int writeLength = -1;
        private readonly byte[] readBuffer = new byte[4096];
        private readonly byte[] writeBuffer = new byte[4096];
        private readonly Socket socket;
        private readonly IConnectionUtility connectionUtility;
    }
}