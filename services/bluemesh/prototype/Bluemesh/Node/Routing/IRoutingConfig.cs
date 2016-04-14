using System;

namespace Node.Routing
{
    internal interface IRoutingConfig
    {
        int DesiredConnections { get; set; }
        int MaxConnections { get; set; }

        TimeSpan ConnectCooldown { get; set; }
        TimeSpan DisconnectCooldown { get; set; }
        TimeSpan MapUpdateCooldown { get; set; }
    }
}