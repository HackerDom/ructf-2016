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
using Node.Serialization;

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
            var node = CreateNode(config, config, "storage");
            var consoleServer = new ConsoleServer(new IPEndPoint(IPAddress.Any, 16801), node);
            consoleServer.Start();
            node.Start();
        }

        private static TcpAddress GetLocalAddress(int port)
        {
            foreach (var @interface in NetworkInterface.GetAllNetworkInterfaces())
            {
                //Console.WriteLine(@interface.Name);
                var info = @interface.GetIPProperties().UnicastAddresses
                    .Where(i => i.Address.AddressFamily == AddressFamily.InterNetwork)
                    .FirstOrDefault(i => Regex.IsMatch(i.Address.ToString(), AddressRegex));
                if (info == null)
                    continue;
                return new TcpAddress(new IPEndPoint(info.Address, port));
            }
            throw new Exception("Could not find interface 10.23.*.3 to listen on!");
        }

        private static BluemeshNode CreateNode(IConnectionConfig connectionConfig, IRoutingConfig routingConfig, string storagePath)
        {
            var encryptionManager = new EncryptionManager(((TcpAddress)connectionConfig.LocalAddress).Endpoint, connectionConfig.KeySendCooldown);
            var connectionManager = new TcpConnectionManager(connectionConfig, routingConfig, encryptionManager);
            var routingManager = new RoutingManager(connectionManager, routingConfig);
            var dataManager = new DataManager(LoadStorage(storagePath) ?? new DataStorage(), storagePath, routingManager, encryptionManager);
            return new BluemeshNode(routingManager, connectionManager, dataManager, encryptionManager, routingConfig.DoLogMap);
        }

        private static IDataStorage LoadStorage(string path)
        {
            try
            {
                using (var stream = File.OpenRead(path))
                {
                    var deserializer = new StreamDeserializer(stream);
                    return DataStorage.Deserialize(deserializer);
                }
            }
            catch
            {
                Console.WriteLine("!! Cannot load data storage from '{0}'", path);
            }
            return null;
        }
    }

    internal class BluemeshNode
    {
        public BluemeshNode(RoutingManager routingManager, TcpConnectionManager connectionManager, DataManager dataManager, EncryptionManager encryptionManager, bool doLogMap)
        {
            this.routingManager = routingManager;
            this.connectionManager = connectionManager;
            this.dataManager = dataManager;
            this.encryptionManager = encryptionManager;
            this.doLogMap = doLogMap;
        }

        public void Start()
        {
            encryptionManager.GenerateKeyPair(BitConverter.GetBytes(connectionManager.Address.GetHashCode()));
            encryptionManager.Start();
            while (true)
            {
                lock (dataManager)
                    Tick();
                Thread.Sleep(TimeSpan.FromMilliseconds(10));
            }
        }

        public void PutFlag(string key, string flag, IAddress destination)
        {
            lock (dataManager)
                dataManager.DispatchData(key, Encoding.UTF8.GetBytes(flag), destination);
        }

        public string GetFlag(string key, IAddress source, TimeSpan timeout)
        {
            var trigger = new ManualResetEventSlim();
            string flag = null;
            Action<DataMessage> action = m =>
            {
                if (m.Action == DataAction.None && m.Key == key)
                {
                    flag = Encoding.UTF8.GetString(m.Data);
                    trigger.Set();
                }
            };
            dataManager.OnReceivedData += action;
            try
            {
                lock (dataManager)
                    dataManager.RequestData(key, source);
                trigger.Wait(timeout);

                return flag;
            }
            finally
            {
                dataManager.OnReceivedData -= action;
            }
        }
        public ICollection<RoutingMapLink> Map { get; private set; }

        private void Tick()
        {
            connectionManager.PurgeDeadConnections();
            var selectResult = connectionManager.Select();

            routingManager.UpdateConnections();

            foreach (var connection in selectResult.ReadableConnections.Where(c => c.State == ConnectionState.Connected))
            {
                for (int i = 0; i < 3 && connection.Socket.Available > 0; i++)
                {
                    var message = connection.Receive();
                    if (!routingManager.ProcessMessage(message, connection))
                        dataManager.ProcessMessage(message, connection);
                }
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

            if (doLogMap)
                Console.WriteLine("[{0}] v: {2} {1}", routingManager.Map.OwnAddress, routingManager.Map, routingManager.Map.Version);
            //if (dataManager.DataStorage.ToString().Length > 0)
            //    Console.WriteLine("[{0}] !! my flags : {1}", routingManager.Map.OwnAddress, dataManager.DataStorage);
            Map = routingManager.Map.Links.ToList();
        }

        private readonly RoutingManager routingManager;
        private readonly TcpConnectionManager connectionManager;
        private readonly DataManager dataManager;
        private readonly EncryptionManager encryptionManager;
        private readonly bool doLogMap;
    }

    internal class ConsoleServer
    {
        public ConsoleServer(IPEndPoint endpoint, BluemeshNode node)
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
            listenerSocket.Listen(5);
            while (true)
            {
                var client = listenerSocket.Accept();
                Task.Factory.StartNew(() => ProcessRequest(client));
            }
        }

        private void ProcessRequest(Socket client)
        {
            using (var stream = new NetworkStream(client))
            {
                var reader = new StreamReader(stream);
                var writer = new StreamWriter(stream);
                try
                {

                    var command = reader.ReadLine();
                    var response = ExecuteCommand(command);
                    writer.WriteLine(response ?? "nodata");
                    writer.Flush();
                }
                catch (Exception e)
                {
                    writer.WriteLine(e);
                    writer.Flush();
                    Console.WriteLine("!! Error in ConsoleServer: " + e);
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
                return node.GetFlag(parts[2], address, TimeSpan.FromSeconds(9));
            }
            if (parts[0] == "list")
            {
                return string.Join(", ", GraphHelper.GetNodes(node.Map));
            }
            return null;
        }

        private Socket listenerSocket;
        private readonly IPEndPoint endpoint;
        private readonly BluemeshNode node;
        private readonly TcpUtility utility;
    }
}
