using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Configuration;
using Microsoft.AspNet.Identity;

namespace ServiceA
{
    public static class ServiceA
    {
        public static void Main(string[] args)
        {
            //Your program starts here...
            Console.WriteLine("Hello World!");

            Vulnerability.process();


            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = 6,
            };

        }

    }
}
