using System;
using System.Collections.Generic;
using System.Linq;
using Node.Connections;
using Node.Messages;

namespace Node.Routing
{
    internal class RoutingManager : IRoutingManager
    {
        public RoutingManager(IConnectionManager connectionManager, IRoutingConfig config)
        {
            this.connectionManager = connectionManager;
            versionsByPeer = new Dictionary<IAddress, VersionInfo>();
            Map = new RoutingMap(connectionManager.Address, config);
        }

        public void PullMaps(IEnumerable<IConnection> readyConnections)
        {
            foreach (var connection in readyConnections)
            {
                var message = connection.Receive() as MapMessage;
                if (message == null)
                    continue;
                Map.Merge(message.Links);
            }
        }

        public void PushMaps(IEnumerable<IConnection> readyConnections)
        {
            foreach (var connection in readyConnections)
            {
                VersionInfo existingVersion;
                if (!versionsByPeer.TryGetValue(connection.RemoteAddress, out existingVersion) ||
                    (existingVersion.Version != Map.Version ||
                     DateTime.UtcNow - existingVersion.Timestamp > TimeSpan.FromMilliseconds(50)))
                {
                    var message = new MapMessage(Map.Links);
                    SendResult result;
                    do
                    {
                        result = connection.Send(message);
                    } while (result == SendResult.Partial);
                    Console.WriteLine("!! {0} -> {1} : {2}", Map.OwnAddress, connection.RemoteAddress, result);

                    if (result == SendResult.Success)
                        versionsByPeer[connection.RemoteAddress] = new VersionInfo(Map.Version, DateTime.UtcNow);
                }
            }
        }

        public void UpdateConnections()
        {
            Console.WriteLine("!! conns : " + 
                string.Join(", ", connectionManager.EstablishedConnections.Select(c => Map.OwnAddress + " <-> " + c.RemoteAddress)) + " ; " + 
                string.Join(", ", connectionManager.Connections.Select(c => Map.OwnAddress + " <-> " + c.RemoteAddress)));
            foreach (var connection in connectionManager.EstablishedConnections)
            {
                Map.AddDirectConnection(connection.RemoteAddress);
            }
            foreach (var peer in GraphHelper.GetPeers(Map.OwnAddress, Map.Links).ToList())
            {
                if (!connectionManager.EstablishedConnections.Any(c => Equals(c.RemoteAddress, peer)))
                    Map.RemoveDirectConnection(peer);
            }
        }

        public void ConnectNewLinks()
        {
            if (DateTime.UtcNow - lastConnect < TimeSpan.FromSeconds(0.2))
                return;
            foreach (var peer in connectionManager.GetAvailablePeers())
            {
                if (Map.ShouldConnectTo(peer) && connectionManager.TryConnect(peer))
                {
                    lastConnect = DateTime.UtcNow;
                    break;
                }
            }
        }

        public void DisconnectExcessLinks()
        {
            if (DateTime.UtcNow - lastDisconnect < TimeSpan.FromSeconds(1))
                return;
            var excessPeer = Map.FindExcessPeer();
            if (excessPeer != null)
            {
                var connection = connectionManager.Connections.FirstOrDefault(c => Equals(c.RemoteAddress, excessPeer));
                if (connection != null)
                {
                    connection.Close();
                    lastDisconnect = DateTime.UtcNow;
                }
            }
        }

        public IRoutingMap Map { get; }
        
        private readonly IConnectionManager connectionManager;
        private readonly Dictionary<IAddress, VersionInfo> versionsByPeer; 
        private DateTime lastDisconnect = DateTime.MinValue;
        private DateTime lastConnect = DateTime.MinValue;

        private struct VersionInfo
        {
            public VersionInfo(int version, DateTime timestamp)
            {
                Version = version;
                Timestamp = timestamp;
            }

            public readonly int Version;
            public readonly DateTime Timestamp;
        }
    }
}