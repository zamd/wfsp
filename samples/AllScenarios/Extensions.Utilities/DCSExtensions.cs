using System.IO;
using System.Runtime.Serialization;

namespace Extensions.Utilities
{
    public static class DCSExtensions
    {
        public static string ToXml<T>(this DataContractSerializer source, T obj)
        {
            var ms = new MemoryStream();
            source.WriteObject(ms, obj);
            ms.Flush();
            ms.Seek(0, SeekOrigin.Begin);
            var sr = new StreamReader(ms);

            var xml = sr.ReadToEnd();
            sr.Close();
            return xml;

        }
    }
}
