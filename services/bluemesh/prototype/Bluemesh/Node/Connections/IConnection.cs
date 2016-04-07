using System.Threading.Tasks;
using Node.Messages;

namespace Node.Connections
{
    internal interface IConnection
    {
        IAddress RemoteAddress { get; }

        SendResult Send(IMessage message);

        IMessage Receive();

        void Close();

        ConnectionState State { get; }
    }
}