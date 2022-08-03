using System.IO;

namespace Bitmessage.Global
{
    public interface INetworkSerializable
    {
        void Deserialize(Stream Input);
        void Serialize(Stream Output);
    }
}
