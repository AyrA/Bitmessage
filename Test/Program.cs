using Bitmessage.Global;
using Bitmessage.Network;
using Bitmessage.Network.Objects;
using Bitmessage.Storage;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace Test
{
    public class Program
    {
        //INFO: Outdated
        //private static readonly List<byte[]> PendingInv = new List<byte[]>();

        private static readonly Peers PeerList = new Peers();

        private static readonly string PeerFile = @"C:\Temp\Bitmessage.Peers.dat";

        private static readonly string DatabaseFile = @"C:\Temp\Bitmessage.Objects";

        private static IPAddress LocalAddr = IPAddress.Any;

        private static IndexedStorage Storage;

        static async Task Main()
        {
            CheckNativeMethods();
            TestAddress();
            return;
            LoadPeers();
            Print.Info("Loading storage");
            Storage = new IndexedStorage(DatabaseFile);
            Print.Info("Storage has {0} objects.", Storage.Count);
            CleanupStorage();
            await GetPublicIP();
            Print.Info("Have {0} peers from last run", PeerList.KnownNodes.Count);
            Print.Info("Connecting...");
            using var Connection = await Connecter.ConnectAsync("bootflix.stream", 8448);
            Print.Info("Connected to {0}", Connection.RemoteEndpoint);
            Connection.NewMessage += Connection_NewMessage;
            Connection.NetworkError += Connection_NetworkError;

            Connection.Start();
            Connection.SendLocalVersion();

            do
            {
                Console.Error.WriteLine("Press [ESC] to exit");
            } while (Console.ReadKey(true).Key != ConsoleKey.Escape);
            Print.Info("Saving peers...");
            SavePeers();
            Print.Info("Saved {0} peers", PeerList.KnownNodes.Count);
            Print.Info("Saving database...");
            Storage.TrimDatabase(NativeMethods.GetFreeMemory() > Storage.DatabaseSize * 2, true);
            Print.Info("Saved {0} objects", Storage.Count);
        }

        private static void TestAddress()
        {
            Print.Info("Creating a test address...");
            var TestAddress = Bitmessage.Cryptography.AddressGenerator.GenerateAddress(false);
            Print.Info("Address: {0}", TestAddress.EncodedAddress);
            Print.Info("Valid  : {0}", Bitmessage.Cryptography.AddressInfo.CheckAddress(TestAddress.EncodedAddress));
            Print.Info("Version: {0}", TestAddress.AddressVersion);
            Print.Info("Stream : {0}", TestAddress.AddressStream);
            //Change stream and version number
            Print.Info("Changing address properties");
            TestAddress.ComputeEncodedAddress(20UL, 99UL);
            Print.Info("Address: {0}", TestAddress.EncodedAddress);
            Print.Info("Valid  : {0}", Bitmessage.Cryptography.AddressInfo.CheckAddress(TestAddress.EncodedAddress));
            Print.Info("Version: {0}", TestAddress.AddressVersion);
            Print.Info("Stream : {0}", TestAddress.AddressStream);
        }

        private static void CleanupStorage()
        {
            int purged = 0;
            var PurgeCutoff = DateTime.UtcNow.AddHours(1);
            foreach (var Item in Storage.EnumerateAllContent())
            {
                var Expiration = Tools.FromUnixTime(Tools.ToUInt64(Item, 8));
                if (Expiration < PurgeCutoff)
                {
                    var Hash = Tools.DoubleSha512(Item).Take(IndexedStorage.INDEX_SIZE).ToArray();
                    if (!Storage.DeleteData(Hash))
                    {
                        Print.Err("Failed to delete hash {0}", Convert.ToBase64String(Hash));
                    }
                    ++purged;
                }
            }
            Print.Info("Purged {0} expired entries from the database", purged);
        }

        private static async Task GetPublicIP()
        {
            Print.Debug("Detecting public IP addresses...");
            await PublicIP.GetBothIPAsync();
            Print.Info("IPv4: {0}", PublicIP.LastV4 == null ? "<none>" : PublicIP.LastV4.ToString());
            Print.Info("IPv6: {0}", PublicIP.LastV6 == null ? "<none>" : PublicIP.LastV6.ToString());
            if (PublicIP.LastV4 == null && PublicIP.LastV6 == null)
            {
                Print.Warn("Failed to detect IPv4 and IPv6 at the same time.");
                Print.Warn("There's a problem with either your internet connection or the IP address service.");
            }
        }

        private static void CheckNativeMethods()
        {
            try
            {
                NativeMethods.CompareBytes(new byte[2], new byte[] { 0, 1 });
            }
            catch (Exception ex)
            {
                FailHard("Crash in NativeMethods.CompareBytes()", ex);
                return;
            }
            try
            {
                NativeMethods.DoPOW(new byte[64], ulong.MaxValue >> 8);
            }
            catch (Exception ex)
            {
                FailHard("Crash in NativeMethods.DoPOW()", ex);
                return;
            }
            if (NativeMethods.UsingSlowByteCompare)
            {
                Print.Warn("Using slow byte compare. Fast compare library is unavailable");
            }
            if (NativeMethods.UsingSlowPOW)
            {
                Print.Warn("Using slow POW. Fast POW library is unavailable");
            }
        }

        private static void FailHard(string msg, Exception ex)
        {
            var ExList = new List<Exception>();
            Console.ForegroundColor = ConsoleColor.Black;
            Console.BackgroundColor = ConsoleColor.Red;
            Console.Write("FATAL ERROR".PadRight(Console.BufferWidth, ' '));
            Console.ForegroundColor = ConsoleColor.Red;
            Console.BackgroundColor = ConsoleColor.Black;
            Console.WriteLine(msg);
            Console.WriteLine("Details:");
            while (ex != null)
            {
                if (ExList.Contains(ex))
                {
                    Console.WriteLine("## Recursive exception tree detected ##");
                    break;
                }
                Console.WriteLine("Type    = {0}", ex.GetType().Name);
                Console.WriteLine("Message = {0}", ex.Message);
                Console.WriteLine("Source  = {0}", ex.Source);
                Console.WriteLine("Trace   = {0}", ex.StackTrace);
                Console.WriteLine(string.Empty.PadRight(Console.BufferWidth, '-'));
                ExList.Add(ex);
                ex = ex.InnerException;
            }
            Console.ResetColor();
            Environment.Exit(int.MaxValue);
        }

        private static void SavePeers()
        {
            using var FS = File.Create(PeerFile);
            PeerList.Purge(Peers.DefaultLifetime);
            PeerList.Serialize(FS);
        }

        private static bool LoadPeers()
        {
            try
            {
                using var FS = File.OpenRead(PeerFile);
                PeerList.KnownNodes.AddRange(Peers.Deserialize(FS).KnownNodes);
                PeerList.Purge(Peers.DefaultLifetime);
                return true;
            }
            catch
            {
                //NOOP: Ignore failing peer load
            }
            return false;
        }

        //INFO: Outdated
        /*
        private static bool AddHash(byte[] Hash)
        {
            lock (PendingInv)
            {
                if (!PendingInv.Any(m => NativeMethods.CompareBytes(m, Hash)))
                {
                    PendingInv.Add(Hash);
                    return true;
                }
            }
            return false;
        }

        private static void AddHashes(IEnumerable<byte[]> enumerable)
        {
            lock (PendingInv)
            {
                //Combine the lists and filter
                var Items = PendingInv
                    .Concat(enumerable)
                    .Distinct(new ByteArrayComparer(true))
                    .ToList();
                //Store result
                PendingInv.Clear();
                PendingInv.AddRange(Items);
            }
        }
        //*/

        private static void Connection_NetworkError(NetworkHandler sender, Exception obj)
        {
            Print.Err("Network error: {0}", obj.Message);
        }

        private static void Connection_NewMessage(NetworkHandler sender, Message obj)
        {
            if (!obj.VerifyChecksum())
            {
                Print.Err("Message type={0} has invalid checksum", obj.MessageType);
            }
            switch (obj.MessageType.ToLower())
            {
                case "error":
                    var ErrorMessage = obj.DeserializePayload<ErrorMessage>();
                    Print.Err("Error received: {0}", ErrorMessage.ErrorText);
                    break;
                case "version":
                    var VersionData = obj.DeserializePayload<Bitmessage.Network.Objects.Version>();
                    Print.Info("Received remote version. UA={0}", VersionData.UserAgent);
                    Print.Info("According to them we are IP={0}", VersionData.ReceiveAddress.Address);
                    LocalAddr = VersionData.ReceiveAddress.Address;
                    ClearLocalAddr(VersionData.ReceiveAddress.Address);
                    sender.SendMessage(new Message("verack"));
                    if (sender.HandshakeCompleted)
                    {
                        SendAddr(sender);
                        AdvertiseHashes(sender);
                    }
                    break;
                case "verack":
                    Print.Info("Local version acknowledged by remote party");
                    if (sender.HandshakeCompleted)
                    {
                        SendAddr(sender);
                        AdvertiseHashes(sender);
                    }
                    break;
                case "addr":
                    var Addresses = obj.DeserializePayload<AddressList>();
                    Print.Info($"Remote party sent us {Addresses.Addresses.Length} nodes");
                    Print.Debug(string.Join(" ", Addresses.Addresses.Select(m => m.Endpoint.ToString())));

                    int newAddr = 0;
                    foreach (var Addr in Addresses.Addresses)
                    {
                        newAddr += PeerList.Add(Addr.Endpoint) ? 1 : 0;
                    }
                    if (newAddr > 0)
                    {
                        Print.Debug($"Got {newAddr} addresses");
                        ClearIpList();
                        SavePeers();
                    }
                    break;
                case "inv":
                    var Inventory = obj.DeserializePayload<InventoryVector>();
                    Print.Info("Remote has {0} items in inventory", Inventory.Items.Length);
                    //AddHashes(Inventory.Items.Select(m => m.Hash));
                    GetMissingHashes(sender, Inventory.Items);
                    break;
                case "getdata":
                    var RequestedItems = obj.DeserializePayload<InventoryVector>();
                    Print.Info("Remote requests {0} items", RequestedItems.Items.Length);
                    Print.Info("First hash: {0}", Convert.ToBase64String(RequestedItems.Items[0].Hash));
                    SendItems(sender, RequestedItems.Items.Select(m => m.Hash).ToList());
                    break;
                case "object":
                    var messageObject = obj.DeserializePayload<MessageObject>();
                    if (messageObject.Expiration < DateTime.UtcNow)
                    {
                        Print.Info("Ignoring expired object");
                        break;
                    }
                    var PowValid = messageObject.VerifyPOW();
                    var objInvHash = obj.GetInvHash();
                    Print.Info("Got object of type={0}; expires={1}; valid={2}; stream={3}",
                        messageObject.ObjectType,
                        messageObject.Expiration.ToLocalTime(),
                        PowValid,
                        messageObject.StreamNumber);
                    Print.Debug("Hash: {0}", Convert.ToBase64String(objInvHash));
                    if (!PowValid)
                    {
                        Print.Warn("POW value is {0} but should be less than {1}",
                            messageObject.GetDifficulty(),
                            messageObject.GetTargetDifficulty()
                            );
                    }
                    else
                    {
                        var currentDiff = messageObject.GetDifficulty();
                        var maxDiff = messageObject.GetTargetDifficulty();
                        var Perc = (double)currentDiff / maxDiff;
                        Print.Debug("POW value is {0:N} of maximum {1:N} ({2:P})",
                            currentDiff,
                            maxDiff,
                            Perc
                            );
                        using var MS = new MemoryStream();
                        messageObject.Serialize(MS);
                        Storage.AddData(MS.ToArray());
                    }
                    break;
                default:
                    Print.Warn("Unknown message: type={0}; size={1}", obj.MessageType, obj.PayloadLength);
                    break;
            }
        }

        private static void SendItems(NetworkHandler sender, List<byte[]> hashes)
        {
            foreach (var H in hashes)
            {
                var Data = Storage.GetData(H);
                if (Data != null)
                {
                    var M = new Message("object", Data);
                    sender.SendMessage(M);
                    Print.Info("Sending object with hash {0}", Convert.ToBase64String(H));
                }
            }
        }

        private static void AdvertiseHashes(NetworkHandler sender)
        {
            var Hashes = Storage.GetAllHashes(false)
                .Select(m => new InventoryItem()
                {
                    Hash = m
                })
                .ToArray();
            if (Hashes.Length == 0)
            {
                Print.Info("We don't have any objects to advertise");
                return;
            }
            var M = new Message("inv", new InventoryVector()
            {
                Items = Hashes
            });
            Print.Info("Advertising {0} objects", Hashes.Length);
            sender.SendMessage(M);
        }

        private static void GetMissingHashes(NetworkHandler sender, InventoryItem[] items)
        {
            if (items == null || items.Length == 0)
            {
                return;
            }
            //Get all missing entries
            var Filtered = items
                .Select(m => m.Hash)
                .Where(m => !Storage.UndeleteData(m))
                .ToList();
            RequestHashes(sender, Filtered);
        }

        private static void ClearIpList()
        {
            ClearLocalAddr(LocalAddr);
            int purged = PeerList.PurgeInvalid();
            if (purged > 0)
            {
                Print.Debug("Purged {0} rejected addresses from IP list", purged);
            }
        }

        private static void ClearLocalAddr(IPAddress Addr)
        {
            if (!Addr.IsIPv4MappedToIPv6)
            {
                Addr = Addr.MapToIPv6();
            }
            Print.Debug("Purged {0} address entries that refer to us", PeerList.KnownNodes.RemoveAll(m => m.Address.Address.MapToIPv6().Equals(Addr)));
        }

        private static void SendAddr(NetworkHandler sender)
        {
            var Nodes = PeerList.KnownNodes.Select(m => new NetworkAddress()
            {
                Address = m.Address.Address,
                Port = (ushort)m.Address.Port,
                Services = VersionServices.NetworkNode,
                Stream = 1,
                Timestamp = m.LastAttempt
            }).ToArray();
            var Obj = new Message("addr", new AddressList() { Addresses = Nodes });
            sender.SendMessage(Obj);
        }

        private static void RequestHashes(NetworkHandler sender, IEnumerable<byte[]> hashes)
        {
            var GetData = new GetData() { Items = hashes.Select(m => new InventoryItem() { Hash = m }).ToArray() };
            if (GetData.Items.Length > 0)
            {
                var M = new Message("getdata", GetData);
                Print.Info("Requesting {0} hashes from remote", GetData.Items.Length);
                sender.SendMessage(M);
            }
            else
            {
                Print.Info("Requesting no hashes from remote");
            }
        }
    }
}
