using System;
using System.Collections.Generic;
using Node.Connections;
using Node.Routing;

namespace Node
{
    internal class StaticConfig : IConnectionConfig, IRoutingConfig
    {
        public IAddress LocalAddress { get; set; }
        public List<IAddress> PreconfiguredNodes { get; set; }
        public TimeSpan KeySendCooldown { get; set; }
        public TimeSpan ConnectingSocketMaxTTL { get; set; }
        public int ConnectingSocketsToConnectionsMultiplier { get; set; }
        public int DesiredConnections { get; set; }
        public int MaxConnections { get; set; }
        public TimeSpan ConnectCooldown { get; set; }
        public TimeSpan DisconnectCooldown { get; set; }
        public TimeSpan MapUpdateCooldown { get; set; }
        public bool LongNames { get; set; }
    }
}