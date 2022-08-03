using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace Bitmessage.Network
{
    public static class PublicIP
    {
        private const string URL_V4 = "https://ip4.ayra.ch/";
        private const string URL_V6 = "https://ip6.ayra.ch/";

        public static IPAddress LastV4 { get; private set; } = null;
        public static IPAddress LastV6 { get; private set; } = null;

        public static async Task GetBothIPAsync()
        {
            await Task.WhenAll(GetIPv4Async(), GetIPv6Async());
        }

        public static async Task<IPAddress> GetIPv4Async()
        {
            try
            {
                return LastV4 = IPAddress.Parse(await HttpDownload(URL_V4));
            }
            catch
            {
                return null;
            }
        }

        public static async Task<IPAddress> GetIPv6Async()
        {
            try
            {
                return LastV6 = IPAddress.Parse(await HttpDownload(URL_V6));
            }
            catch
            {
                return null;
            }
        }

        private static async Task<string> HttpDownload(string URL)
        {
            using var Cli = new HttpClient();
            Cli.Timeout = TimeSpan.FromSeconds(5);
            try
            {
                var Response = await Cli.GetAsync(URL);
                if (Response.StatusCode != HttpStatusCode.OK)
                {
                    throw new WebException($"Server error. Got status code {Response.StatusCode}");
                }
                return (await Response.Content.ReadAsStringAsync()).Trim();
            }
            catch
            {
                return null;
            }
        }
    }
}
