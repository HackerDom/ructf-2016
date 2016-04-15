using System;
using System.Collections.Generic;

namespace Node.Connections
{
    internal interface IConnectionConfig
    {
        IAddress LocalAddress { get; }

        List<IAddress> PreconfiguredNodes { get; }

        TimeSpan KeySendCooldown { get; }

        TimeSpan ConnectingSocketMaxTTL { get; }

        int ConnectingSocketsToConnectionsMultiplier { get; }
    }
}