using System;

namespace Node.Routing
{
    internal interface IRoutingConfig
    {
        int DesiredConnections { get; }
        int MaxConnections { get; }

        TimeSpan ConnectCooldown { get; }
        TimeSpan DisconnectCooldown { get; }
        TimeSpan MapUpdateCooldown { get; }

        bool LongNames { get; }
    }
}