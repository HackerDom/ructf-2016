namespace Node.Routing
{
    internal struct GraphConnectivity
    {
        public GraphConnectivity(int connectedComponents, int biconnectedComponents)
        {
            ConnectedComponents = connectedComponents;
            BiconnectedComponents = biconnectedComponents;
        }

        public readonly int ConnectedComponents;
        public readonly int BiconnectedComponents;
    }
}