using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Node.Connections.Tcp;
using Node.Routing;

namespace CheckerNode
{
    internal class ExtraConsoleServer
    {
        public ExtraConsoleServer(IPEndPoint endpoint, CheckerNode node)
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
                ProcessRequest(client);
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
            if (parts[0] == "connect")
            {
                if (parts.Length != 2)
                    return null;
                var address = utility.ParseAddress(parts[1]);
                if (address == null)
                    return null;
                node.Connect(address);
                return "done";
            }
            if (parts[0] == "disconnect")
            {
                if (parts.Length != 2)
                    return null;
                var address = utility.ParseAddress(parts[1]);
                if (address == null)
                    return null;
                node.Disconnect(address);
                return "done";
            }
            return null;
        }

        private Socket listenerSocket;
        private readonly IPEndPoint endpoint;
        private readonly CheckerNode node;
        private readonly TcpUtility utility;
    }
}