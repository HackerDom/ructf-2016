using System.Threading.Tasks;
using Node.Messages;

namespace Node.Connections
{
    internal interface IConnection
    {
        IAddress RemoteAddress { get; }

        string RemoteName { get; }
        IAddress LocalAddress { get; }

        string LocalName { get; }

        SendResult Send(IMessage message);

        IMessage Receive();

        void Tick(bool canRead);

        void Close();

        ConnectionState State { get; }
    }
}