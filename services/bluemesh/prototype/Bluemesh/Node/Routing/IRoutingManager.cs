using System.Collections.Generic;
using Node.Connections;

namespace Node.Routing
{
    internal interface IRoutingManager
    {
        void PullMaps(IEnumerable<IConnection> readyConnections);
        void PushMaps(IEnumerable<IConnection> readyConnections);
        void ConnectNewLinks();
        void DisconnectExcessLinks();
        IRoutingMap Map { get; }
    }
}