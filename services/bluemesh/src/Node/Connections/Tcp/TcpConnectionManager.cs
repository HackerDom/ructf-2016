using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Node.Encryption;
using Node.Routing;

namespace Node.Connections.Tcp
{
    internal class TcpConnectionManager : IConnectionManager
    {
        public TcpConnectionManager(IConnectionConfig connectionConfig, IRoutingConfig routingConfig, IEncryptionManager encryptionManager)
        {
            this.connectionConfig = connectionConfig;
            this.routingConfig = routingConfig;
            this.encryptionManager = encryptionManager;
            connections = new List<TcpConnection>();
            connectingSockets = new List<SocketInfo>();
            Utility = new TcpUtility();
            CreateListener();
        }

        public List<IAddress> GetAvailablePeers()
        {
            var peers = connectionConfig.PreconfiguredNodes.Where(address => !Equals(address, Address)).ToList();
            encryptionManager.RetrievePeerKeys(peers);
            return peers;
        }

        public bool TryConnect(IAddress address)
        {
            var tcpAddress = address as TcpAddress;
            if (tcpAddress == null)
                return false;

            if (connections.Any(c => Equals(c.RemoteAddress, address)) || connectingSockets.Any(s => Equals(s.RemoteEndPoint, tcpAddress.Endpoint)))
                return true;

            if (GetUsedConnectionSlots() >= routingConfig.MaxConnections)
                return false;

            //Console.WriteLine("!! connecting to {0} ; existing sockets : {1} ; existing conns : {2}", tcpAddress, connectingSockets.Count, 
            //    string.Join(", ", connections.Select(c => c.RemoteAddress)));
            
            var socket = Connect(tcpAddress.Endpoint);
            if (socket != null)
            {
                connectingSockets.Add(new SocketInfo(socket, tcpAddress.Endpoint, DateTime.UtcNow));
                return true;
            }

            return false;
        }

        public void PurgeDeadConnections()
        {
            connections.RemoveAll(c => c.State > ConnectionState.Connected || !c.Socket.IsOk());
            var badSockets = null as List<SocketInfo>;
            foreach (var info in connectingSockets)
            {
                if (DateTime.UtcNow - info.Timestamp <= connectionConfig.ConnectingSocketMaxTTL)
                    continue;
                if (badSockets == null)
                    badSockets = new List<SocketInfo>(connectingSockets.Count);
                badSockets.Add(info);
            }
            if (badSockets == null)
                return;
            foreach (var info in badSockets)
            {
                info.Socket.Close();
                connectingSockets.Remove(info);
            }

            //Console.WriteLine("!! garbage : {0} conns; {1} sockets", connections.Count(c => c.State != ConnectionState.Connected), connectingSockets.Count);
        }

        public SelectResult Select()
        {
            var checkRead = new[] { serverSocket }.Concat(connections.Select(c => c.Socket)).ToList();
            var checkWrite = connectingSockets.Select(info => info.Socket).Concat(connections.Select(c => c.Socket)).ToList();
            var checkError = connectingSockets.Select(info => info.Socket).Concat(connections.Select(c => c.Socket)).ToList();

            try
            {
                if (checkRead.Count + checkWrite.Count + checkError.Count > 0)
                    Socket.Select(checkRead, checkWrite, checkError, 100 * 1000);
            }
            catch (SocketException e)
            {
                Console.WriteLine("Select : " + e.Message);
                foreach (var connection in connections)
                {
                    connection.Close();
                }
                PurgeDeadConnections();
                return null;
            }
            //Console.WriteLine("[{3}] Select : {0} {1} {2}", checkRead.Count, checkWrite.Count, checkError.Count, Address);
            if (checkRead.Contains(serverSocket))
            {
                //Console.WriteLine("!! {0} accept : {1} + {2} < {3}", Address, Connections.Count, connectingSockets.Count, routingConfig.MaxConnections);
                var socket = serverSocket.Accept();
                var address = new TcpAddress((IPEndPoint)socket.RemoteEndPoint);
                if (connections.Any(c => c.RemoteAddress.Equals(address)) || connections.Count >= routingConfig.MaxConnections)
                {
                    socket.Close();
                }
                else
                    connections.Add(CreateConnection(address, socket));

            }
            foreach (var socket in checkWrite)
            {
                if (!socket.Connected)
                    continue;
                if (connectingSockets.RemoveAll(s => s.Socket == socket) > 0)
                {
                    var address = new TcpAddress((IPEndPoint) socket.RemoteEndPoint);
                    if (connections.Any(c => c.RemoteAddress.Equals(address)) || connections.Count >= routingConfig.MaxConnections)
                    {
                        socket.Close();
                        continue;
                    }
                    connections.Add(CreateConnection(address, socket));
                }
            }
            foreach (var socket in checkError)
            {
                try
                {
                    connectingSockets.RemoveAll(s => s.Socket == socket);
                    socket.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to close socket: " + e);
                }
            }
            return new SelectResult(
                connections.Where(c => checkRead.Contains(c.Socket)).ToList(),
                connections.Where(c => checkWrite.Contains(c.Socket)).ToList());
        }
        public void Stop()
        {
            serverSocket.Close();
            foreach (var info in connectingSockets)
                info.Socket.Close();
            foreach (var connection in Connections)
                connection.Close();
        }

        public List<IConnection> Connections => new List<IConnection>(connections);

        public IEnumerable<IConnection> EstablishedConnections => Connections.Where(c => c.State == ConnectionState.Connected); 

        public IConnectionUtility Utility { get; }

        public IAddress Address => connectionConfig.LocalAddress;

        private TcpConnection CreateConnection(TcpAddress address, Socket socket)
        {
            var connection = new TcpConnection((TcpAddress)Address, address, socket, Utility, encryptionManager);
            connection.ValidateConnection += conn =>
                EstablishedConnections.Count() < routingConfig.MaxConnections &&
                (StringComparer.OrdinalIgnoreCase.Compare(conn.LocalAddress.ToString(), conn.RemoteAddress.ToString()) >= 0 || 
                connections.All(c => ReferenceEquals(c, conn) || c.State != ConnectionState.Connected || !Equals(c.RemoteAddress, conn.RemoteAddress)));
            return connection;
        }

        private int GetUsedConnectionSlots()
        {
            return connections.Count + connectingSockets.Count / connectionConfig.ConnectingSocketsToConnectionsMultiplier;
        }

        private Socket Connect(IPEndPoint endpoint)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { Blocking = false };
            try
            {
                socket.Connect(endpoint);
                return socket;
            }
            catch (SocketException e)
            {
                if (e.ErrorCode == (int) SocketError.WouldBlock)
                    return socket;
                Console.WriteLine("[{0}] Failed to connect to " + endpoint + ": " + e.Message, Address);
                return null;
            }
        }

        private void CreateListener()
        {
            serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { Blocking = false };
            serverSocket.Bind(((TcpAddress)connectionConfig.LocalAddress).Endpoint);
            serverSocket.Listen(1);
        }
        
        private Socket serverSocket;
        private readonly List<TcpConnection> connections;
        private readonly List<SocketInfo> connectingSockets;
        private readonly IConnectionConfig connectionConfig;
        private readonly IRoutingConfig routingConfig;
        private readonly IEncryptionManager encryptionManager;

        private struct SocketInfo
        {
            public SocketInfo(Socket socket, IPEndPoint remoteEndPoint, DateTime timestamp)
            {
                Socket = socket;
                RemoteEndPoint = remoteEndPoint;
                Timestamp = timestamp;
            }

            public readonly Socket Socket;
            public readonly IPEndPoint RemoteEndPoint;
            public readonly DateTime Timestamp;
        }
    }
}