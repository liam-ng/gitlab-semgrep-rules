using System;
using System.Xml;

namespace ServiceB
{
    public static class ServiceB
    {
        public static void Main(string[] args)
        {
            //Your program starts here...
            Console.WriteLine("Hello World!");

            XmlInject();
        }

        public static string XmlInject()
        {
            //Your program starts here...
            Console.WriteLine("Hello World!");

            var input = "okay";
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load("/config.xml");
            var results = doc.SelectNodes("/Config/Devices/Device[id='" + input + "']");
            return results.ToString();
        }

    }
}
