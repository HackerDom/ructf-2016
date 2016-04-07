using System.Collections.Generic;
using System.Threading.Tasks;

namespace Node.Connections
{
    internal interface IConnectionManager
    {
        List<IAddress> GetAvailablePeers();

        void Connect(IAddress address);

        void PurgeDeadConnections();

        List<IConnection> Connections { get; }

        IConnectionUtility Utility { get; }

        IAddress Address { get; }
    }
}