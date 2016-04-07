namespace Node.Connections.LocalTcp
{
    internal class LocalTcpUtility : IConnectionUtility
    {
        public IAddress ParseAddress(string s)
        {
            return new LocalTcpAddress(int.Parse(s));
        }
    }
}