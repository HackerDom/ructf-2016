using System.Collections.Generic;

namespace Node.Connections
{
    internal interface IConnectionConfig
    {
        IAddress LocalAddress { get; }

        List<IAddress> PreconfiguredNodes { get; } 
    }
}