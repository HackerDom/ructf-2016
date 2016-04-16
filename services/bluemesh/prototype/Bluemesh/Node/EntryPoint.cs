using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Node.Connections;
using Node.Connections.Tcp;
using Node.Data;
using Node.Encryption;
using Node.Messages;
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
                ConnectingSocketMaxTTL = TimeSpan.FromMilliseconds(50),
                ConnectingSocketsToConnectionsMultiplier = 5,
                PreconfiguredNodes = Enumerable.Range(1, 30).Select(i => new TcpAddress(new IPEndPoint(IPAddress.Parse(string.Format(AddressFormat, i)), 16800)) as IAddress).ToList(),
                LocalAddress = GetLocalAddress(16800),
                LongNames = true
            };
            var node = CreateNode(config, config);
            var consoleServer = new ConsoleServer(new IPEndPoint(IPAddress.Loopback, 16801), node);
            consoleServer.Start();
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
            var encryptionManager = new EncryptionManager(((TcpAddress)connectionConfig.LocalAddress).Endpoint, connectionConfig.KeySendCooldown);
            var connectionManager = new TcpConnectionManager(connectionConfig, routingConfig, encryptionManager);
            var routingManager = new RoutingManager(connectionManager, routingConfig);
            var dataManager = new DataManager(new DataStorage(), "", routingManager, encryptionManager);
            return new TestNode(routingManager, connectionManager, dataManager, encryptionManager);
        }

        private class TestNode
        {
            public TestNode(RoutingManager routingManager, TcpConnectionManager connectionManager, DataManager dataManager, EncryptionManager encryptionManager)
            {
                this.routingManager = routingManager;
                this.connectionManager = connectionManager;
                this.dataManager = dataManager;
                this.encryptionManager = encryptionManager;
            }

            public void Start()
            {
                encryptionManager.GenerateKeyPair(BitConverter.GetBytes(connectionManager.Address.GetHashCode()));
                encryptionManager.Start();
                while (!Stopped)
                {
                    Tick();
                    Thread.Sleep(TimeSpan.FromMilliseconds(10));
                }
                connectionManager.Stop();
                encryptionManager.Stop();
                Console.WriteLine("Stopped node {0}", connectionManager.Address);
            }

            public bool Stopped { get; set; }

            public void PutFlag(string key, string flag, IAddress destination)
            {
                dataManager.DispatchData(key, Encoding.UTF8.GetBytes(flag), destination);
            }

            public string GetFlag(string key, IAddress source)
            {
                var trigger = new ManualResetEventSlim();
                string flag = null;
                dataManager.OnReceivedData += m =>
                {
                    if (m.Action == DataAction.None && m.Key == key)
                    {
                        flag = Encoding.UTF8.GetString(m.Data);
                        trigger.Set();
                    }
                };
                dataManager.RequestData(key, source);
                trigger.Wait();
                return flag;
            }

            public ICollection<RoutingMapLink> Map { get; private set; }

            private void Tick()
            {
                connectionManager.PurgeDeadConnections();
                var selectResult = connectionManager.Select();

                routingManager.UpdateConnections();

                foreach (var connection in selectResult.ReadableConnections.Where(c => c.State == ConnectionState.Connected))
                {
                    var message = connection.Receive();
                    if (!routingManager.ProcessMessage(message, connection))
                        dataManager.ProcessMessage(message, connection);
                }
                routingManager.PushMaps(selectResult.WritableConnections.Where(c => c.State == ConnectionState.Connected));
                dataManager.PushMessages(selectResult.WritableConnections.Where(c => c.State == ConnectionState.Connected));

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
                if (dataManager.DataStorage.ToString().Length > 0)
                    Console.WriteLine("[{0}] !! my flags : {1}", routingManager.Map.OwnAddress, dataManager.DataStorage);
                Map = routingManager.Map.Links.ToList();
            }

            private readonly RoutingManager routingManager;
            private readonly TcpConnectionManager connectionManager;
            private readonly DataManager dataManager;
            private readonly EncryptionManager encryptionManager;
        }

        private class ConsoleServer
        {
            public ConsoleServer(IPEndPoint endpoint, TestNode node)
            {
                this.endpoint = endpoint;
                this.node = node;
                utility = new TcpUtility();
            }

            public void Start()
            {
                new Thread(Listen).Start();
            }

            private void Listen()
            {
                listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                listenerSocket.Bind(endpoint);
                listenerSocket.Listen(1);
                while (true)
                {
                    var client = listenerSocket.Accept();
                    try
                    {
                        using (var stream = new NetworkStream(client))
                        {
                            var reader = new StreamReader(stream);
                            var writer = new StreamWriter(stream);

                            var command = reader.ReadLine();
                            var response = ExecuteCommand(command);
                            if (response != null)
                            {
                                writer.WriteLine(response);
                                writer.Flush();
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
            }

            private string ExecuteCommand(string command)
            {
                var parts = command.Split(' ');
                if (parts.Length == 0)
                    return null;
                if (parts[0] == "put")
                {
                    if (parts.Length != 4)
                        return null;
                    var address = utility.ParseAddress(parts[1]);
                    if (address == null)
                        return null;
                    node.PutFlag(parts[2], parts[3], address);
                    return "done";
                }
                if (parts[0] == "get")
                {
                    if (parts.Length != 3)
                        return null;
                    var address = utility.ParseAddress(parts[1]);
                    if (address == null)
                        return null;
                    return node.GetFlag(parts[2], address);
                }
                if (parts[0] == "list")
                {
                    return string.Join(", ", GraphHelper.GetNodes(node.Map));
                }
                return null;
            }

            private Socket listenerSocket;
            private readonly IPEndPoint endpoint;
            private readonly TestNode node;
            private readonly TcpUtility utility;
        }
    }
}
