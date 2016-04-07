using System.Collections.Generic;

namespace Node.Connections.LocalTcp
{
    internal class SelectResult
    {
        public SelectResult(List<LocalTcpConnection> readableConnections, List<LocalTcpConnection> writableConnections)
        {
            ReadableConnections = readableConnections;
            WritableConnections = writableConnections;
        }

        public readonly List<LocalTcpConnection> ReadableConnections;
        public readonly List<LocalTcpConnection> WritableConnections;
    }
}