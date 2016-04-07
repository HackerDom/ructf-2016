namespace Node.Routing
{
    internal interface IRoutingManager
    {
        void PullMaps();
        void PushMaps();
        IRoutingMap Map { get; }
    }
}