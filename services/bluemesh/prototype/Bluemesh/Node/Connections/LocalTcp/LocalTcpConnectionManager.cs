using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Node.Routing;

namespace Node.Connections.LocalTcp
{
    internal class LocalTcpConnectionManager : IConnectionManager
    {
        public LocalTcpConnectionManager(IRoutingConfig routingConfig)
        {
            this.routingConfig = routingConfig;
            connections = new List<LocalTcpConnection>();
            connectingSockets = new List<SocketInfo>();
            Utility = new LocalTcpUtility();

            var foundPort = false;
            for (int port = LocalTcpAddress.MinPort; port <= LocalTcpAddress.MaxPort; port++)
                if (foundPort = TryCreateListener(port))
                    break;
            if (!foundPort)
                throw new Exception("Failed to find a free port!");
            Address = new LocalTcpAddress(((IPEndPoint)serverSocket.LocalEndPoint).Port);
        }

        public List<IAddress> GetAvailablePeers()
        {
            return Directory.GetFiles(".", "*.lock")
                .Select(Path.GetFileNameWithoutExtension)
                .Select(int.Parse)
                .Select(i => new LocalTcpAddress(i) as IAddress)
                .Where(addr => !Equals(addr, Address))
                .ToList();
        }

        public bool TryConnect(IAddress address)
        {
            var tcpAddress = address as LocalTcpAddress;
            if (tcpAddress == null)
                return false;

            if (connections.Any(c => Equals(c.RemoteAddress, address)))
                return true;

            if (GetUsedConnectionSlots() >= routingConfig.MaxConnections)
                return false;
            
            var socket = TryConnect(tcpAddress.Port);
            if (socket != null)
            {
                connectingSockets.Add(new SocketInfo(socket, DateTime.UtcNow));
                return true;
            }

            return false;
        }

        public void PurgeDeadConnections()
        {
            connections.RemoveAll(c => c.State > ConnectionState.Connected || !c.Socket.Connected);
            foreach (var info in connectingSockets.Where(s => DateTime.UtcNow - s.Timestamp > TimeSpan.FromSeconds(1)).ToList())
            {
                info.Socket.Close();
                connectingSockets.Remove(info);
            }

            Console.WriteLine("!! garbage : {0} conns; {1} sockets", connections.Count(c => c.State != ConnectionState.Connected), connectingSockets.Count);
        }

        public SelectResult Select()
        {
            List<Socket> checkRead, checkWrite, checkError;
            if (GetUsedConnectionSlots() < routingConfig.MaxConnections)
            {
                checkRead = new[] { serverSocket }.Concat(connections.Select(c => c.Socket)).ToList();
                checkWrite = connectingSockets.Select(info => info.Socket).Concat(connections.Select(c => c.Socket)).ToList();
                checkError = connectingSockets.Select(info => info.Socket).Concat(connections.Select(c => c.Socket)).ToList();
            }
            else
            {
                checkRead = connections.Select(c => c.Socket).ToList();
                checkWrite = connectingSockets.Select(info => info.Socket).Concat(connections.Select(c => c.Socket)).ToList();
                checkError = connectingSockets.Select(info => info.Socket).Concat(connections.Select(c => c.Socket)).ToList();
            }

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
            /*if (checkRead.Contains(tcpListener.Server))
            {
                Console.WriteLine("!! {0} accept : {1} + {2} < {3}", Address, Connections.Count, connectingSockets.Count, routingConfig.MaxConnections);
                var socket = tcpListener.AcceptSocket();
                if (socket.Blocking)
                    throw new Exception("FUCK");
                var address = new LocalTcpAddress(((IPEndPoint)socket.RemoteEndPoint).Port);
                if (connections.Any(c => c.RemoteAddress.Equals(address)))
                {
                    socket.Close();
                }
                else
                    connections.Add(new LocalTcpConnection(address, socket, Utility));

            }*/
            foreach (var socket in checkWrite)
            {
                if (connectingSockets.RemoveAll(s => s.Socket == socket) > 0)
                {
                    var address = new LocalTcpAddress(((IPEndPoint) socket.RemoteEndPoint).Port);
                    if (connections.Any(c => c.RemoteAddress.Equals(address)))
                    {
                        socket.Close();
                        continue;
                    }
                    connections.Add(new LocalTcpConnection(address, socket, Utility));
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
                    Console.WriteLine("MEGAFUCK: " + e);
                }
            }
            return new SelectResult(
                connections.Where(c => checkRead.Contains(c.Socket)).ToList(),
                connections.Where(c => checkWrite.Contains(c.Socket)).ToList());
        }

        public List<IConnection> Connections => new List<IConnection>(connections);

        public IEnumerable<IConnection> EstablishedConnections => Connections.Where(c => c.State == ConnectionState.Connected); 

        public IConnectionUtility Utility { get; }
        public IAddress Address { get; }

        private int GetUsedConnectionSlots()
        {
            return connections.Count + connectingSockets.Count;
        }

        private Socket TryConnect(int port)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { Blocking = false };
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.Bind(serverSocket.LocalEndPoint);
            try
            {
                socket.Connect(IPAddress.Loopback, port);
                return socket;
            }
            catch (SocketException e)
            {
                if (e.ErrorCode == (int) SocketError.WouldBlock)
                    return socket;
                Console.WriteLine("[{0}] Failed to connect to " + port + ": " + e.Message, Address);
                return null;
            }
        }

        private bool TryCreateListener(int port)
        {
            serverSocket = new Socket(SocketType.Stream, ProtocolType.Tcp) { Blocking = false };
            serverSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            try
            {
                serverSocket.Bind(new IPEndPoint(IPAddress.Loopback, port));

                if (TryCreateLock(port))
                {
                    //serverSocket.Listen(5);
                    return true;
                }

                serverSocket.Close();
                return false;
            }
            catch
            {
                serverSocket.Close();
                return false;
            }
        }

        private bool TryCreateLock(int id)
        {
            var path = new LocalTcpAddress(id) + ".lock";
            try
            {
                lockHolder = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose);
                return true;
            }
            catch (IOException)
            {
                return false;
            }
        }

        private FileStream lockHolder;
        private Socket serverSocket;
        private readonly List<LocalTcpConnection> connections;
        private readonly List<SocketInfo> connectingSockets;
        private readonly IRoutingConfig routingConfig;

        private struct SocketInfo
        {
            public SocketInfo(Socket socket, DateTime timestamp)
            {
                Socket = socket;
                Timestamp = timestamp;
            }

            public readonly Socket Socket;
            public readonly DateTime Timestamp;
        }
    }
}