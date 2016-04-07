using Node.Connections;

namespace Node.Routing
{
    internal class RoutingManager : IRoutingManager
    {
        public RoutingManager(IConnectionManager connectionManager)
        {
            this.connectionManager = connectionManager;
        }

        public IRoutingMap Map { get; }
        
        private readonly IConnectionManager connectionManager;
    }
}