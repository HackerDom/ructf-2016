namespace Node.Routing
{
    internal interface IRoutingManager
    {
        void PullMaps();
        void PushMaps();
        void ConnectNewLinks();
        void DisconnectExcessLinks();
        IRoutingMap Map { get; }
    }
}