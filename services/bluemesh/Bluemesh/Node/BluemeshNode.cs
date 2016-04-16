using Node.Connections;

namespace Node
{
    internal class BluemeshNode
    {
        public BluemeshNode(IConnectionManager connectionManager)
        {
            ConnectionManager = connectionManager;
        }

        public IConnectionManager ConnectionManager { get; }
    }
}