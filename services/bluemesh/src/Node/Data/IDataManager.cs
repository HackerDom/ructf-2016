using System;
using System.Collections.Generic;
using Node.Connections;
using Node.Messages;

namespace Node.Data
{
    internal interface IDataManager
    {
        bool ProcessMessage(IMessage message, IConnection connection);
        void PushMessages(IEnumerable<IConnection> readyConnections);
        void FlushData();

        void DispatchData(string key, byte[] data, IAddress destination);
        void RequestData(string key, IAddress destination);
        event Action<DataMessage> OnReceivedData;

        void PullPendingMessage(IConnection connection);

        IDataStorage DataStorage { get; }
    }
}