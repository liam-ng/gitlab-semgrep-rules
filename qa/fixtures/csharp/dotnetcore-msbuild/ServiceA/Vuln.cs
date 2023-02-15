using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServiceA
{
    public static class Vulnerability
    {
        public static string process()
        {

            var input = "hi";
            var p = new Process();
            p.StartInfo.FileName = "exportLegacy.exe";
            p.StartInfo.Arguments = " -user " + input + " -role user";
            p.Start();
            return "process done";
        }
    }
}
