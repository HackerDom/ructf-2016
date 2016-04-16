using System.Collections.Generic;
using Node.Connections;
using Node.Messages;

namespace Node.Routing
{
    internal interface IRoutingManager
    {
        bool ProcessMessage(IMessage message, IConnection connection);
        void PushMaps(IEnumerable<IConnection> readyConnections);
        void ConnectNewLinks();
        void DisconnectExcessLinks();
        IRoutingMap Map { get; }
    }
}