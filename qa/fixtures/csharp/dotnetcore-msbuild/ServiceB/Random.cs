using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServiceB
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
