using System;

namespace WebLib
{
    public static class GetRandom
    {
        public static string RandomNumber()
        {
            var rnd = new Random();
            byte[] buffer = new byte[16];
            rnd.NextBytes(buffer);
            return BitConverter.ToString(buffer);
        }
    }
}
