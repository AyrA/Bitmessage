# C# Bitmessage Client

This is a Bitmessage client written in C# that tries to solve the biggest problems of the official client:

1. The client is a big mess of code that's very difficult to find your way through
2. Being written in Python, it's not great performance wise
3. Python code is extremely unfriendly to port to different languages due to the absence of static typing
4. Third party library usage that's difficult to set up (seriously, try getting the source code running on Windows)

# Project structure

The project is split into multiple individual components.
Once completed, this will allow you to pick individual components you're interested in.

**Examples:**

- Remove the user interface and replace it with a web client
- Use only the networking part and integrate it into a chat application

## Bitmessage.Global

This holds the basic stuff. All other components depend on this component.
Here you find things such as:

- Native methods
- POW
- VarInt handler
- Big endian data handler

## Bitmessage.Network

This component contains the classes that represent all the objects sent through the network.
It also contains a class you can use that speaks the bitmessage network protocol.

## Bitmessage.Storage

This component contains classes relevant for storing objects on disk.
Currently, there's two main classes for this.

The `Peers` class, that holds IP and port information.

The `IndexedStorage`, this is a simple storage that stores arbitrary data and allows retrieval by hash.
It should be completely thread safe.
The hash the storage uses is on purpose chosen to match that of the bitmessage network objects:
the first 32 bytes of `Sha512(Sha512(data))`.

The test project stores all network objects in this store,
but in theory you can store any kind of binary data in it.
Due to the hashing it comes with deduplication built in.
Similar to SQLite, data that is deleted is simply marked as such,
and you have to call a special function to permanently remove the data from the database.

If you are unhappy with how primitive this thing it is, you can write your own storage engine
or use a 3rd party storage engine such as SQLite or MariaDB.
I do believe it's "good enough" for Bitmessage.

## Test

This is a console application that is used to test individual features and make them interact.

In the current state it will:

- Connect to a single hardcoded node
- Authenticate
- Download all items it doesn't has already
- Upload any item requested by the remote
- Use Bitmessage.Storage to permanently store downloaded objects

In other words, the test project is a fully functional relay.

It has no interactivity as of now.

# Available but unused in the Test project

Since POW has been implemented already,
you can in its current state send custom objects over the network,
and the other clients will accept, store, and forward them.

This means you can implement your own cryptographic routines,
and use the bitmessage network to merely transport your objects to other clients.

Encrypted messages in bitmessage have no special format and are just binary data.
Nothing stops you from sending unencrypted data over the network if you want to.

# Native functions

This project makes use of some native functions that may only exist on Windows.
For other systems, a fallback is often available.

## Array compare

Byte array comparison in .NET is kinda slow,
so a native import of the C function `memcmp()` is used instead.
In case this is unavailable, .NET mechanisms are used instead.

## Free memory

The storage engine requires a temporary file to purge the data
in a matter that is safe against crashes.
Provided enough memory is available, a RAM file is used instead of the file system.

Detecting free memory is necessary for this purpose.
Since this works differently on different systems,
a Windows API call is used.
On non-Windows platforms, the information is obtained from `/proc/meminfo` instead.

## POW

POW (proof of work) requires repeatedly doing the same dumb hash calculation
over and over again until a satisfactory result is obtained.

This is very slow in .NET, and thus a C library is used instead.
Later, an OpenCL library with GPU support will be added for even more performance.

**There is currently no alternative to this**.
If you want to compile this for a non-Windows OS,
you also have to adapt the function to use a native library written for your OS,
or write and endure the very slow .NET mechanism.
The code for the library can be found in the original bitmessage client repository.
It's a simple C library that depends on `libeay32` from OpenSSL.
If you do that, consider creating a pull request with the compiled library,
so it can be added to the repository.

# TODO

*Not necessarily in order of importance*

- GPU accelerated POW function
- Address generator and validator
- Public key request handler
- Encryption and decryption function
- TLS\*
- UI

\* Later versions of the official bitmessage client support TLS,
but only a single uncommon cipher `AECDH-AES256-SHA` as per the docs.
This cipher lacks authentication and has other problems,
Because of this, TLS is fairly low on the priority list.

# Completed steps

- Implement basic networking component and protocol
- Implement all network objects\*
- Implement persistent storage for objects and peers
- Implement POW function

\* "ping" and "pong" are not implemented, but they do not carry any data anyways.
These two functions aren't even contained in the official documentation in the wiki,
and they crash the networking threads of some older clients.

# Links

- Fast POW source: [GitHub](https://github.com/Bitmessage/PyBitmessage/tree/master/src/bitmsghash)
- Unsafe TLS cipher: [AECDH-AES256-SHA](https://ciphersuite.info/cs/TLS_ECDH_anon_WITH_AES_256_CBC_SHA/)
- Protocol documentation: [Bitmessage Wiki](https://wiki.bitmessage.org/index.php/Protocol_specification)
- More instructions: [More](https://youtu.be/dQw4w9WgXcQ)
