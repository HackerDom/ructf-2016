using System;
using System.Net.Sockets;

namespace Node.Connections.Tcp
{
    internal static class SocketExtensions
    {
        public static int ReceiveSafe(this Socket socket, byte[] buffer, int offset, int count)
        {
            //if (socket.Available == 0)
            //    return 0;
            if (socket.Available == 0)
                Console.WriteLine("!! ALERT: sick motherfuckers want me to read {0} bytes from empty sock!", count);
            
            return socket.Receive(buffer, offset, count, SocketFlags.None);
        }
        public static int SendSafe(this Socket socket, byte[] buffer, int offset, int count)
        {
            return socket.Send(buffer, offset, count, SocketFlags.None);
        }
    }
}