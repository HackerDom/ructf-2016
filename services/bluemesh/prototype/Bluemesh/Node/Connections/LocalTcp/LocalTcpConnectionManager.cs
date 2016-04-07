using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Node.Connections.LocalTcp
{
    internal class LocalTcpConnectionManager : IConnectionManager
    {
        public LocalTcpConnectionManager()
        {
            connections = new List<LocalTcpConnection>();
            connectingSockets = new List<Socket>();
            Utility = new LocalTcpUtility();

            for (int port = LocalTcpAddress.MinPort; port <= LocalTcpAddress.MaxPort; port++)
                if (TryCreateListener(port))
                    break;
            if (tcpListener == null)
                throw new Exception("Failed to find a free port!");
            Address = new LocalTcpAddress(((IPEndPoint)tcpListener.LocalEndpoint).Port);
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

        public void Connect(IAddress address)
        {
            var tcpAddress = address as LocalTcpAddress;
            if (tcpAddress == null)
                return;

            if (connections.Any(c => Equals(c.RemoteAddress, address)))
                return;
            
            var socket = TryConnect(tcpAddress.Port);
            if (socket != null)
                connectingSockets.Add(socket);
        }

        public void PurgeDeadConnections()
        {
            connections.RemoveAll(c => c.State != ConnectionState.Connected || !c.Socket.Connected);
        }

        public SelectResult Select()
        {
            var checkRead = new[] { tcpListener.Server }.Concat(connections.Select(c => c.Socket)).ToList();
            var checkWrite = connectingSockets.Concat(connections.Select(c => c.Socket)).ToList();
            var checkError = connectingSockets.Concat(connections.Select(c => c.Socket)).ToList();
            try
            {
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
            if (checkRead.Contains(tcpListener.Server))
            {
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

            }
            foreach (var socket in checkWrite)
            {
                if (connectingSockets.Remove(socket))
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
                    connectingSockets.Remove(socket);
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

        public IConnectionUtility Utility { get; }
        public IAddress Address { get; }

        private Socket TryConnect(int port)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { Blocking = false };
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.Bind(tcpListener.LocalEndpoint);
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
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Server.Blocking = false;
            listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            try
            {
                listener.Start();

                if (TryCreateLock(port))
                {
                    tcpListener = listener;
                    return true;
                }

                return false;
            }
            catch
            {
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
        private TcpListener tcpListener;
        private readonly List<LocalTcpConnection> connections;
        private readonly List<Socket> connectingSockets;
    }
}