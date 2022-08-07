using Bitmessage.Global;
using Bitmessage.Network.Objects;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Bitmessage.Network
{
    public class NetworkHandler : IDisposable
    {
        public const int TIMEOUT_INIT = 20_000;
        public const int TIMEOUT_REGULAR = 600_000;

        public event Action<NetworkHandler, Exception> NetworkError = delegate { };

        public event Action<NetworkHandler, Message> NewMessage = delegate { };

        public IPEndPoint LocalEndpoint { get; }
        public IPEndPoint RemoteEndpoint { get; }

        public Objects.Version VersionSent { get; private set; }
        public Objects.Version VersionReceived { get; private set; }

        public bool RemoteVersionAcknowledgedByLocal { get; private set; }

        public bool LocalVersionAcknowledgedByRemote { get; private set; }

        public bool HandshakeCompleted { get => RemoteVersionAcknowledgedByLocal && LocalVersionAcknowledgedByRemote; }

        private NetworkStream stream;

        private Thread networkThread;

        private readonly object senderLock = new object();

        public NetworkHandler(Socket Client)
        {
            LocalEndpoint = (IPEndPoint)Client.LocalEndPoint;
            RemoteEndpoint = (IPEndPoint)Client.RemoteEndPoint;
            stream = new NetworkStream(Client, true);
            stream.WriteTimeout = stream.ReadTimeout = TIMEOUT_INIT;
        }

        public Objects.Version CreateLocalVersion()
        {
            return new Objects.Version()
            {
                Nonce = BitConverter.ToUInt64(Tools.GetSafeRandomBytes(8)),
                ProtocolVersion = VersionProtocol.Version3,
                Services = VersionServices.NetworkNode,
                ReceiveAddress = new NetworkAddress()
                {
                    Address = RemoteEndpoint.Address,
                    Port = (ushort)RemoteEndpoint.Port,
                    Services = VersionServices.NetworkNode,
                    Stream = 1,
                    Timestamp = DateTime.UtcNow
                },
                SendAddress = new NetworkAddress()
                {
                    Address = LocalEndpoint.Address,
                    Port = (ushort)LocalEndpoint.Port,
                    Services = VersionServices.NetworkNode,
                    Stream = 1,
                    Timestamp = DateTime.UtcNow
                },
                Streams = new ulong[] { 1 },
                Timestamp = DateTime.UtcNow,
                UserAgent = Tools.USER_AGENT
            };
        }

        public void SendLocalVersion()
        {
            SendMessage(new Message("version", CreateLocalVersion()));
            stream.ReadTimeout = stream.WriteTimeout = TIMEOUT_REGULAR;
        }

        public void Start()
        {
            if (networkThread != null)
            {
                throw new InvalidOperationException("Thread already running");
            }
            networkThread = new Thread(HandleConnection)
            {
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            networkThread.Start();
        }

        public void SendMessage(Message M)
        {
            if (M is null)
            {
                throw new ArgumentNullException(nameof(M));
            }
            if (M.MessageType == "version")
            {
                VersionSent = M.DeserializePayload<Objects.Version>();
            }
            else if (M.MessageType == "verack")
            {
                RemoteVersionAcknowledgedByLocal = true;
            }
            //Make sure only one send operation is ongoing at the same time
            lock (senderLock)
            {
                M.Serialize(stream);
            }
        }

        public void SendRawData(byte[] Data)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }
            if (Data.Length > 0)
            {
                lock (senderLock)
                {
                    stream.Write(Data, 0, Data.Length);
                }
            }
        }

        private void HandleConnection()
        {
            while (true)
            {
                Message M = new Message();
                try
                {
                    M.Deserialize(stream);
                }
                catch (Exception ex)
                {
                    NetworkError(this, ex);
                    break;
                }
                if (M.MessageType == "version" && VersionReceived == null)
                {
                    VersionReceived = M.DeserializePayload<Objects.Version>();
                }
                else if (M.MessageType == "verack")
                {
                    LocalVersionAcknowledgedByRemote = true;
                }
                NewMessage(this, M);
            }
            var s = stream;
            if (s != null)
            {
                s.Close();
            }
        }

        public void Dispose()
        {
            var s = stream;
            stream = null;
            if (s != null)
            {
                s.Dispose();
            }
        }
    }
}
