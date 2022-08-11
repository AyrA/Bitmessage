using Bitmessage.Cryptography;
using Bitmessage.Global;
using Bitmessage.Network;
using Bitmessage.Network.Objects;
using Bitmessage.Storage;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace Test
{
    public class Program
    {
        private static readonly Peers PeerList = new Peers();

        private static readonly string PeerFile = @"C:\Temp\Bitmessage.Peers.dat";

        private static readonly string DatabaseFile = @"C:\Temp\Bitmessage.Objects";

        private static IPAddress LocalAddr = IPAddress.Any;

        private static IndexedStorage Storage;

        static async Task Main()
        {
            Print.Info("Loading storage");
            Storage = new IndexedStorage(DatabaseFile);
            Print.Info("Storage has {0} objects.", Storage.Count);
            //CleanupStorage();
            CheckNativeMethods();
            //TestAddressGenerator();

            /*
            var Broadcasts = EnumerateBroadcasts("BM-BcbRqcFFSQUUmXFKsPJgVQPSiFA3Xash").ToArray();

            Console.WriteLine("Timeservice count: {0}", Broadcasts.Length);
            if (Broadcasts.Length > 0)
            {
                Console.WriteLine(Broadcasts[0].Content);
            }
            //*/

            var Addr = AddressGenerator.GenerateDeterministicAddress("general", false);

            foreach (var BC in EnumerateMessages(Addr))
            {
                Print.Debug("Found message. Body length: {0} characters", BC.Content.Length);
                //This should in theory be our address
                Print.Info(AddressInfo.GetAddress(BC.DestinationRipe, BC.AddressVersion, BC.StreamNumber));
            }

            /*
            LoadPeers();
            await GetPublicIP();
            Print.Info("Have {0} peers from last run", PeerList.KnownNodes.Count);
            Print.Info("Connecting...");
            using var Connection = await Connecter.ConnectAsync("ovh.ayra.ch", 8448);
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
            //*/
        }

        private static IEnumerable<Bitmessage.Global.Objects.Broadcast> EnumerateBroadcasts(string Address)
        {
            byte[] Hash = AddressInfo.GetBroadcastHash(Address);
            var AddrKey = Hash[..Const.EC.PRIVKEY_LENGTH];
            var AddrTag = Hash[Const.EC.PRIVKEY_LENGTH..];
            var Key = new ECKey(AddrKey);
            foreach (var Entry in Storage.EnumerateAllContent())
            {
                var obj = MessageObject.FromData(Entry);
                if (obj.ObjectType == MessageObjectType.Broadcast)
                {
                    byte[] ObjTag;
                    if (obj.Version == 5)
                    {
                        ObjTag = obj.Payload[..32];
                    }
                    else if (obj.Version == 4)
                    {
                        ObjTag = null;
                    }
                    else
                    {
                        Console.Write('?');
                        continue;
                    }
                    if (ObjTag == null || NativeMethods.CompareBytes(AddrTag, ObjTag))
                    {
                        //Remove tag from payload if present
                        var Payload = ObjTag == null ? obj.Payload : obj.Payload[ObjTag.Length..];

                        //Try to decrypt
                        byte[] Result;
                        try
                        {
                            Result = ObjectDecrypter.DecryptBroadcast(Payload, Key);
                        }
                        catch (Exception ex)
                        {
                            Debug.Print($"Error: {ex.Message}");
                            Console.Write('!');
                            continue;
                        }
                        if (Result != null)
                        {
                            //TODO: Check signature
                            yield return new Bitmessage.Global.Objects.Broadcast(Result);
                        }
                    }
                }
            }
        }

        private static IEnumerable<Bitmessage.Global.Objects.Message> EnumerateMessages(AddressInfo Address)
        {
            foreach (var Entry in Storage.EnumerateAllContent())
            {
                var obj = MessageObject.FromData(Entry);
                if (obj.ObjectType == MessageObjectType.Message)
                {
                    //Try to decrypt
                    byte[] Result;
                    bool hasVersion;
                    try
                    {
                        Result = ObjectDecrypter.DecryptMessage(obj.Payload, Address, out hasVersion);
                    }
                    catch
                    {
                        continue;
                    }
                    if (Result != null)
                    {
                        var msg = new Bitmessage.Global.Objects.Message(Result);

                        //Extract sender address and keys from message
                        var Sender = AddressInfo.FromRawPublicKeys(msg.PubkeyEnc, msg.PubkeySign);
                        Sender.ComputeEncodedAddress(msg.AddressVersion, msg.StreamNumber);

                        //Signature size + the varInt with the size.
                        //Needed to cut off the signature when verifying the data
                        var SignatureSize = VarInt.GetVarIntSize((ulong)msg.Signature.Length) + msg.Signature.Length;

                        //This is the old way of verifying the signature
                        if (Sender.SigningKey.Verify(Result[..^SignatureSize], msg.Signature))
                        {
                            yield return msg;
                        }

                        using var MS = new MemoryStream();
                        using var BW = MS.GetWriter();

                        //If we're here we have to deal with a more complex message signature
                        //The message signature is a horrible mess.
                        //It includes parts of the enclosing structure.
                        //
                        //Signature field description as per the docs:
                        //  The ECDSA signature which covers the object header starting with the time,
                        //  appended with the data described in this table down to the ack_data.
                        //
                        //The pybitmessage client does this:
                        //   signedData = data[8:20] +
                        //      encodeVarint(1) +
                        //      encodeVarint(streamNumberAsClaimedByMsg) +
                        //      decryptedData[:positionOfBottomOfAckData]
                        //
                        // data[8:20] is 12 bytes (expiresTime(4) + objectType(4))
                        // encodeVarint(1) is just an overly complex way of using the byte 0x01
                        // encodeVarint(streamNumberAsClaimedByMsg) is the streamNumber field
                        // decryptedData[:positionOfBottomOfAckData] is all decrypted data up to the end of ack_data

                        //data[8:20]
                        BW.Write(Tools.ToUnixTime(obj.Expiration));
                        BW.Write((uint)obj.ObjectType);

                        //This should not be present after protocol v3 as per the docs,
                        //But the exact opposite seems to be the case.
                        //This is another case of the docs being completely wrong
                        if (hasVersion)
                        {
                            msg.MessageVersion = 1;
                            //obj.SerializeForSignature(MS);
                            //MS.Write(VarInt.EncodeVarInt(1), 0, 1);
                            
                            //encodeVarint(1)
                            BW.WriteVarInt(1);
                        }
                        //encodeVarint(streamNumberAsClaimedByMsg)
                        BW.WriteVarInt(msg.StreamNumber);

                        //decryptedData[:positionOfBottomOfAckData]
                        BW.Write(Result[..^SignatureSize]);
                        BW.Flush();

                        //msg.SerializeForSignature(MS);
                        var SignatureData = MS.ToArray();

                        if (Sender.SigningKey.Verify(SignatureData, msg.Signature))
                        {
                            yield return msg;
                        }
                        else
                        {
                            Print.Warn("Decrypt OK but signature validation failed. This is not supposed to happen");
                            Print.Warn("Sender is {0}", Sender.EncodedAddress);
                            Print.Warn("Rcpt   is {0}", AddressInfo.GetAddress(msg.DestinationRipe, msg.AddressVersion, msg.StreamNumber));
                            Print.Warn("Version : {0}", hasVersion ? 'Y' : 'N');
#if DEBUG
                            yield return msg;
#endif
                        }
                    }
                }
            }
        }

        private static void TestAddressGenerator()
        {
            Stopwatch SW = Stopwatch.StartNew();
            //Random address
            Print.Info("Creating a test address...");
            var TestAddress = AddressGenerator.GenerateRandomAddress(false, 1, 3);
            Print.Info("Address: {0}", TestAddress.EncodedAddress);
            Print.Info("Valid  : {0}", AddressInfo.CheckAddress(TestAddress.EncodedAddress));
            Print.Info("Version: {0}", TestAddress.AddressVersion);
            Print.Info("Stream : {0}", TestAddress.AddressStream);
            Print.Info("Time   : {0} ms", SW.ElapsedMilliseconds);

            //Change stream and version number
            Print.Info("Changing address properties");
            TestAddress.ComputeEncodedAddress(20UL, 99UL);
            Print.Info("Address: {0}", TestAddress.EncodedAddress);
            Print.Info("Valid  : {0}", AddressInfo.CheckAddress(TestAddress.EncodedAddress));
            Print.Info("Version: {0}", TestAddress.AddressVersion);
            Print.Info("Stream : {0}", TestAddress.AddressStream);
            Print.Info(Convert.ToBase64String(TestAddress.SigningKey.SerializePublic(true)));
            //*/

            SW.Restart();
            //Deterministic address
            TestAddress = AddressGenerator.GenerateDeterministicAddress("general", false, 1, 4);
            Print.Info("Address: {0}", TestAddress.EncodedAddress);
            Print.Info("Valid  : {0}", AddressInfo.CheckAddress(TestAddress.EncodedAddress));
            Print.Info("Version: {0}", TestAddress.AddressVersion);
            Print.Info("Stream : {0}", TestAddress.AddressStream);
            Print.Info("Time   : {0} ms", SW.ElapsedMilliseconds);
            //Check if the address is identical to the address generated via PyBitmessage
            Print.Info("Compare: {0}", TestAddress.EncodedAddress == "BM-2cW67GEKkHGonXKZLCzouLLxnLym3azS8r");
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
                    var Hash = Hashing.DoubleSha512(Item).Take(IndexedStorage.INDEX_SIZE).ToArray();
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

        public static void Dump(byte[] Data, params byte[] Highlight)
        {
            var BaseColor = Console.ForegroundColor;
            if (Data is null || Data.Length == 0)
            {
                return;
            }
            Console.Error.WriteLine("Dumping {0} bytes", Data.Length);
            for (var i = 0; i < Data.Length; i += 16)
            {
                var chars = "";
                foreach (var B in Data.Skip(i).Take(16))
                {
                    //Only print lower ASCII without control characters
                    if (B >= 0x20 && B < 0x7F)
                    {
                        chars += (char)B;
                    }
                    else
                    {
                        chars += '.';
                    }
                    Console.ForegroundColor = Highlight.Contains(B) ? ConsoleColor.Red : BaseColor;
                    Console.Error.Write("{0:X2} ", B);
                }
                Console.ResetColor();
                Console.Error.WriteLine("{1}\t{0}", chars, string.Empty.PadRight(3 * (16 - chars.Length)));
            }
        }
    }
}
