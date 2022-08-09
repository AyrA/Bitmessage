using System;

namespace Bitmessage.Global
{
    [Flags]
    public enum Behavior : uint
    {
        DoesAck = 1
    }

    public enum EncodingType : ulong
    {
        Ignore = 0UL,
        Trivial = 1UL,
        Simple = 2UL,
        Extended = 3UL
    }
}
