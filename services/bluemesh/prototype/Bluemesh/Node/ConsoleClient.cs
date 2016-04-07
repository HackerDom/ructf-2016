using System;
using System.Linq;
using Node.Messages;

namespace Node
{
    internal class ConsoleClient
    {
        public ConsoleClient(BluemeshNode node)
        {
            this.node = node;
        }

        public void ExecuteCommand(string line)
        {
            if (line == "")
                return;
            var parts = line.Split(" ".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
            var command = parts[0];
            var args = parts.Skip(1).ToArray();
            switch (command)
            {
                case "list":
                    ListPeers();
                    break;
                case "conns":
                    ListConnections();
                    break;
                case "connect":
                    ConnectPeer(args[0]);
                    break;
                case "disconnect":
                    DisconnectPeer(args[0]);
                    break;
                case "send":
                    SendString(args[0], args[1]);
                    break;
                case "receive":
                    ReceiveString(args[0]);
                    break;
                default:
                    Console.WriteLine("Unrecognized command.");
                    break;
            }
        }

        private void ListConnections()
        {
            foreach (var connection in node.ConnectionManager.Connections)
            {
                Console.WriteLine("{0} : {1}", connection.RemoteAddress, connection.State);
            }
        }

        private void ReceiveString(string addressString)
        {
            var address = node.ConnectionManager.Utility.ParseAddress(addressString);

            var connection = node.ConnectionManager.Connections.FirstOrDefault(c => Equals(c.RemoteAddress, address));
            var result = connection?.Receive();

            if (result == null)
                Console.WriteLine("Failed to find connection.");
            else
                Console.WriteLine(result);
        }

        private void SendString(string addressString, string message)
        {
            var address = node.ConnectionManager.Utility.ParseAddress(addressString);

            var connection = node.ConnectionManager.Connections.FirstOrDefault(c => Equals(c.RemoteAddress, address));
            var result = connection?.Send(new StringMessage(message));

            if (result == null)
                Console.WriteLine("Failed to find connection.");
            else
                Console.WriteLine(result.Value);
        }

        private void DisconnectPeer(string addressString)
        {
            var address = node.ConnectionManager.Utility.ParseAddress(addressString);

            var connection = node.ConnectionManager.Connections.FirstOrDefault(c => Equals(c.RemoteAddress, address));
            connection?.Close();
        }

        private void ConnectPeer(string addressString)
        {
            var address = node.ConnectionManager.Utility.ParseAddress(addressString);
            
            node.ConnectionManager.Connect(address);
        }

        private void ListPeers()
        {
            var peers = node.ConnectionManager.GetAvailablePeers();
            
            foreach (var peer in peers)
                Console.WriteLine(peer);
        }

        private readonly BluemeshNode node;
    }
}