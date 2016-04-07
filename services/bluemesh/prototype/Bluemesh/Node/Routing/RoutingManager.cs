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

        public void PullMaps()
        {
            foreach (var connection in connectionManager.Connections)
            {
                var message = connection.Receive() as MapMessage;
                if (message == null)
                    continue;
                Map.Merge(message.Links);
            }
        }

        public void PushMaps()
        {
            foreach (var connection in connectionManager.Connections)
            {
                VersionInfo existingVersion;
                if (!versionsByPeer.TryGetValue(connection.RemoteAddress, out existingVersion) ||
                    (existingVersion.Version != Map.Version &&
                     DateTime.UtcNow - existingVersion.Timestamp > TimeSpan.FromMilliseconds(100)))
                {
                    var message = new MapMessage(Map.Links);
                    SendResult result;
                    do
                    {
                        result = connection.Send(message);
                    } while (result == SendResult.Partial);

                    if (result == SendResult.Success)
                        versionsByPeer[connection.RemoteAddress] = new VersionInfo(Map.Version, DateTime.UtcNow);
                }
            }
        }

        public void ConnectNewLinks()
        {
            foreach (var peer in connectionManager.GetAvailablePeers())
            {
                if (Map.ShouldConnectTo(peer) && connectionManager.TryConnect(peer))
                {
                    Map.AddDirectConnection(peer);
                    break;
                }
            }
        }

        public void DisconnectExcessLinks()
        {
            var excessPeer = Map.FindExcessPeer();
            if (excessPeer != null)
            {
                var connection = connectionManager.Connections.FirstOrDefault(c => Equals(c.RemoteAddress, excessPeer));
                if (connection != null)
                {
                    connection.Close();
                    connectionManager.PurgeDeadConnections();
                }
                Map.RemoveDirectConnection(excessPeer);
            }
        }

        public IRoutingMap Map { get; }
        
        private readonly IConnectionManager connectionManager;
        private readonly Dictionary<IAddress, VersionInfo> versionsByPeer; 

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