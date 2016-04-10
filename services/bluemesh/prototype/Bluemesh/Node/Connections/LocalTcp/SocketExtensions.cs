using System.Net.Sockets;

namespace Node.Connections.LocalTcp
{
    internal static class SocketExtensions
    {
        public static int ReceiveSafe(this Socket socket, byte[] buffer, int offset, int count)
        {
            if (socket.Available == 0)
                return 0;
            return socket.Receive(buffer, offset, count, SocketFlags.None);
        }
        public static int SendSafe(this Socket socket, byte[] buffer, int offset, int count)
        {
            return socket.Send(buffer, offset, count, SocketFlags.None);
        }
    }
}