using System;
using System.Collections.Generic;

namespace Test
{
    public static class Print
    {
        private static readonly object locker = new object();

        public static void Err(string Line, params object[] args)
        {
            W(ConsoleColor.Red, string.Format(Line, args));
        }

        public static void Err(IEnumerable<string> Lines)
        {
            W(ConsoleColor.Red, string.Join(Environment.NewLine, Lines));
        }

        public static void Warn(string Line, params object[] args)
        {
            W(ConsoleColor.Yellow, string.Format(Line, args));
        }

        public static void Warn(IEnumerable<string> Lines)
        {
            W(ConsoleColor.Yellow, string.Join(Environment.NewLine, Lines));
        }

        public static void Info(string Line, params object[] args)
        {
            W(ConsoleColor.Green, string.Format(Line, args));
        }

        public static void Info(IEnumerable<string> Lines)
        {
            W(ConsoleColor.Green, string.Join(Environment.NewLine, Lines));
        }

        public static void Debug(string Line, params object[] args)
        {
            W(ConsoleColor.White, string.Format(Line, args));
        }

        public static void Debug(IEnumerable<string> Lines)
        {
            W(ConsoleColor.White, string.Join(Environment.NewLine, Lines));
        }

        private static void W(ConsoleColor c, string line)
        {
            lock (locker)
            {
                Console.ForegroundColor = c;
                Console.WriteLine(line);
                Console.ResetColor();
            }
        }
    }
}
