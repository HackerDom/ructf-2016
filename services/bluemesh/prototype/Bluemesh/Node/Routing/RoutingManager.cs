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
            this.config = config;
            versionsByPeer = new Dictionary<IAddress, VersionInfo>();
            Map = new RoutingMap(connectionManager.Address, config);
            random = new Random(connectionManager.Address.GetHashCode());
        }

        public bool ProcessMessage(IMessage message, IConnection connection)
        {
            if (message == null)
                return true;
            return ProcessMap(message as MapMessage, connection);
        }

        public void PushMaps(IEnumerable<IConnection> readyConnections)
        {
            foreach (var connection in readyConnections)
            {
                VersionInfo existingVersion;
                if (!versionsByPeer.TryGetValue(connection.RemoteAddress, out existingVersion) ||
                    (existingVersion.Version != Map.Version ||
                     DateTime.UtcNow - existingVersion.Timestamp > config.MapUpdateCooldown))
                {
                    var message = new MapMessage(Map.Links, false);
                    var result = connection.Push(message);
                    //Console.WriteLine("!! {0} -> {1} : {2}", Map.OwnAddress, connection.RemoteAddress, result);

                    if (result == SendResult.Success)
                        versionsByPeer[connection.RemoteAddress] = new VersionInfo(Map.Version, DateTime.UtcNow);
                }
            }
        }

        public void UpdateConnections()
        {
            Console.WriteLine("[{0}] !! conns : {1}", Map.OwnAddress, 
                string.Join(", ", connectionManager.EstablishedConnections.Select(c => Map.OwnAddress + " <-> " + c.RemoteAddress)));
            foreach (var connection in connectionManager.EstablishedConnections)
            {
                Map.AddDirectConnection(connection.RemoteAddress);
            }
            foreach (var peer in GraphHelper.GetPeers(Map.OwnAddress, Map.Links).ToList())
            {
                if (!connectionManager.EstablishedConnections.Any(c => Equals(c.RemoteAddress, peer)))
                {
                    Map.RemoveDirectConnection(peer);
                }
            }
        }

        public void ConnectNewLinks()
        {
            if (DateTime.UtcNow - lastConnect < config.ConnectCooldown.AdjustForNode(connectionManager.Address))
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
            if (DateTime.UtcNow - lastDisconnect < config.DisconnectCooldown.AdjustForNode(connectionManager.Address))
                return;
            var excessPeer = Map.FindExcessPeer();
            if (excessPeer != null)
            {
                lastDisconnect = DateTime.UtcNow;
                Console.WriteLine("[{0}] suggesting {1} to terminate connection", Map.OwnAddress, excessPeer);
                var connection = connectionManager.Connections.FirstOrDefault(c => Equals(c.RemoteAddress, excessPeer));
                connection?.Push(new MapMessage(Map.Links, true));
            }
        }

        public IRoutingMap Map { get; }

        private bool ProcessMap(MapMessage message, IConnection connection)
        {
            if (message == null)
                return false;
            if (message.SuggestDisconnect)
            {
                if (message.Links.AreEquivalent(Map.Links) && Map.IsLinkExcess(new RoutingMapLink(Map.OwnAddress, connection.RemoteAddress)))
                {
                    Console.WriteLine("[{0}] closing connection with {1} by agreement", Map.OwnAddress, connection.RemoteAddress);
                    connection.Close();
                }
            }
            Map.Merge(message.Links, connection.RemoteAddress);
            return true;
        }

        private readonly IConnectionManager connectionManager;
        private readonly IRoutingConfig config;
        private readonly Dictionary<IAddress, VersionInfo> versionsByPeer;
        private readonly Random random;
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