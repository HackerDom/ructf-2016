using Node.Messages;

namespace Node.Connections
{
    internal interface IConnection
    {
        IAddress RemoteAddress { get; }
        
        IAddress LocalAddress { get; }

        SendResult Send(IMessage message);

        SendResult Send(byte[] rawData);

        SendResult Push(IMessage message);

        SendResult Push(byte[] rawData);

        IMessage Receive();

        void Tick(bool canRead);

        void Close();

        ConnectionState State { get; }
    }
}