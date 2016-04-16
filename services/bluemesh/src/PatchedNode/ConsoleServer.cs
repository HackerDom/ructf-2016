using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Node.Connections.Tcp;
using Node.Routing;

namespace PatchedNode
{
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