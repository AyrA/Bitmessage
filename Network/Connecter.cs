using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Bitmessage.Network
{
    public static class Connecter
    {
        public static event Action<NetworkHandler> Connected = delegate { };
        public static event Action<Exception> ConnectionFailed = delegate { };

        public static void ConnectWithEvent(string IpOrHost, int Port)
        {
            TcpClient C = new TcpClient();
            C.BeginConnect(IpOrHost, Port, NewConnection, C);
        }

        public static async Task<NetworkHandler> ConnectAsync(string IpOrHost, int Port)
        {
            TcpClient C = new TcpClient();
            await C.ConnectAsync(IpOrHost, Port);
            return new NetworkHandler(C.Client);
        }

        private static void NewConnection(IAsyncResult Result)
        {
            TcpClient C = Result.AsyncState as TcpClient;
            try
            {
                C.EndConnect(Result);
            }
            catch (Exception ex)
            {
                ConnectionFailed(ex);
                return;
            }
            Connected(new NetworkHandler(C.Client));
        }
    }
}
