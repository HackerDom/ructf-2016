using System;
using System.Collections.Generic;
using Node.Connections;

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
            throw new NotImplementedException();
        }

        public void PushMaps()
        {
            throw new NotImplementedException();
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