using System.Collections.Generic;

namespace Node.Connections.Tcp
{
    internal class SelectResult
    {
        public SelectResult(List<TcpConnection> readableConnections, List<TcpConnection> writableConnections)
        {
            ReadableConnections = readableConnections;
            WritableConnections = writableConnections;
        }

        public readonly List<TcpConnection> ReadableConnections;
        public readonly List<TcpConnection> WritableConnections;
    }
}