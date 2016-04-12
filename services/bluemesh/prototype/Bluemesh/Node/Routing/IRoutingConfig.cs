namespace Node.Routing
{
    internal interface IRoutingConfig
    {
        int DesiredConnections { get; set; }
        int MaxConnections { get; set; }
    }
}