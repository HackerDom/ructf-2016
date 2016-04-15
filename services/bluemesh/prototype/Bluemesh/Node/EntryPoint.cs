using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Node.Connections;
using Node.Connections.Tcp;
using Node.Encryption;
using Node.Routing;

namespace Node
{
    internal class EntryPoint
    {
        //private const string AddressFormat = "10.23.{0}.3";
        //private const string AddressRegex = @"^10\.23\.\d+\.3$";
        private const string AddressFormat = "172.16.16.1{0:00}";
        private const string AddressRegex = @"^172\.16\.16\.1\d+$";

        private static void Main(string[] args)
        {
            var config = new StaticConfig
            {
                DesiredConnections = 3,
                MaxConnections = 20,
                ConnectCooldown = TimeSpan.FromMilliseconds(100),
                DisconnectCooldown = TimeSpan.FromMilliseconds(100),
                MapUpdateCooldown = TimeSpan.FromMilliseconds(50),
                KeySendCooldown = TimeSpan.FromSeconds(10),
                PreconfiguredNodes = Enumerable.Range(1, 30).Select(i => new TcpAddress(new IPEndPoint(IPAddress.Parse(string.Format(AddressFormat, i)), 16800)) as IAddress).ToList(),
                LocalAddress = GetLocalAddress(16800),
                LongNames = true
            };
            var node = CreateNode(config, config);
            node.Start();
        }

        private static TcpAddress GetLocalAddress(int port)
        {
            foreach (var @interface in NetworkInterface.GetAllNetworkInterfaces())
            {
                Console.WriteLine(@interface.Name);
                var info = @interface.GetIPProperties().UnicastAddresses
                    .Where(i => i.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .FirstOrDefault(i => Regex.IsMatch(i.Address.ToString(), AddressRegex));
                if (info == null)
                    continue;
                return new TcpAddress(new IPEndPoint(info.Address, port));
            }
            throw new Exception("Could not find interface 10.23.*.3 to listen on!");
        }

        private static TestNode CreateNode(IConnectionConfig connectionConfig, IRoutingConfig routingConfig)
        {
            var encryptionManager = new EncryptionManager(((TcpAddress) connectionConfig.LocalAddress).Endpoint, connectionConfig.KeySendCooldown);
            var connectionManager = new TcpConnectionManager(connectionConfig, routingConfig, encryptionManager);
            return new TestNode(new RoutingManager(connectionManager, routingConfig), connectionManager);
        }

        private class TestNode
        {
            public TestNode(RoutingManager routingManager, TcpConnectionManager connectionManager)
            {
                this.routingManager = routingManager;
                this.connectionManager = connectionManager;
            }

            public void Start()
            {
                while (!Stopped)
                {
                    Tick();
                    Thread.Sleep(TimeSpan.FromMilliseconds(10));
                }
                connectionManager.Stop();
                Console.WriteLine("Stopped node {0}", connectionManager.Address);
            }

            public bool Stopped { get; set; }

            private void Tick()
            {
                connectionManager.PurgeDeadConnections();
                var selectResult = connectionManager.Select();

                routingManager.UpdateConnections();

                foreach (var connection in selectResult.ReadableConnections.Where(c => c.State == ConnectionState.Connected))
                {
                    var message = connection.Receive();
                    routingManager.ProcessMessage(message, connection);
                }
                routingManager.PushMaps(selectResult.WritableConnections.Where(c => c.State == ConnectionState.Connected));

                routingManager.DisconnectExcessLinks();
                routingManager.ConnectNewLinks();

                foreach (var connection in selectResult.ReadableConnections)
                {
                    //Console.WriteLine("[{0}] tick: {1} -> {2}", connectionManager.Address, connectionManager.Address, connection.RemoteAddress);
                    connection.Tick(true);
                }
                foreach (var connection in selectResult.WritableConnections)
                {
                    //Console.WriteLine("[{0}] tick: {1} -> {2}", connectionManager.Address, connectionManager.Address, connection.RemoteAddress);
                    connection.Tick(false);
                }

                Console.WriteLine("[{0}] v: {2} {1}", routingManager.Map.OwnAddress, routingManager.Map, routingManager.Map.Version);
            }

            private readonly RoutingManager routingManager;
            private readonly TcpConnectionManager connectionManager;
        }
    }
}
