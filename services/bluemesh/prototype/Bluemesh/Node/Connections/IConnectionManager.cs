using System.Collections.Generic;
using System.Threading.Tasks;

namespace Node.Connections
{
    internal interface IConnectionManager
    {
        List<IAddress> GetAvailablePeers();

        bool TryConnect(IAddress address);

        void PurgeDeadConnections();

        List<IConnection> Connections { get; }
        IEnumerable<IConnection> EstablishedConnections { get; }

        IConnectionUtility Utility { get; }

        IAddress Address { get; }

        void Stop();
    }
}