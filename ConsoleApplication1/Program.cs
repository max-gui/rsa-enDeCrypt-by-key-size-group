using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
            RSACryptoServiceProvider rcp = new RSACryptoServiceProvider(2048);
            RSACryptoServiceProvider rcp1 = new RSACryptoServiceProvider(1024);
            var str = "1234567890987654321qwertyuioplkjhgfdsazxcvbnmmnbvcxzasdfghjklpoiuytrewq1234567890987654321qwertyuioplkjhgfdsazxcvbnmmnbvcxzasdfghjklpoiuytrewq1234567890987654321qwertyuioplkjhgfdsazxcvbnmmnbvcxzasdfghjklpoiuytrewq1234567890987654321qwertyuioplkjhgfdsazxcvbnmmnbvcxzasdfghjklpoiuytrewq";

            //var m = new StringBuilder(str);
            //var m1 = m.ToString(0, ll);
            //m.Remove(0, ll);
            //var m2 = m.ToString();

            //str = "fdsa";
            //var enText = rcp.Encrypt(planText,false);

            //signvar 
            //planTextData = Encoding.UTF8.GetBytes(planText);            
            //var mds = rcp.SignData(planText, new SHA1CryptoServiceProvider());
            
            var enText = DisFunc<byte[]>(() => en(rcp, str), "2048 e time");

            var enText2 = DisFunc<byte[]>(() => en(rcp1, str), "1024 e time");

            var res = DisFunc<string>(() => de(rcp, enText), "2048 d time");
            var res2 = DisFunc<string>(() => de(rcp1, enText2), "1024 d time");

            var flag = res.Equals(str);
            flag = res2.Equals(str);

            Console.ReadLine();

        }

        private static T DisFunc<T>(Func<T> f,string message)
        {
            var t1 = Environment.TickCount;
            var res = f();
            var t1End = Environment.TickCount;
            Console.WriteLine(message + " : " + (t1End - t1));

            return res;
        }

        private static string de(RSACryptoServiceProvider rcp, byte[] enText)
        {
            var ll = rcp.KeySize / 8 - 11;
            var ll2 = ll + 11;

            var res = string.Empty;
            using (MemoryStream CrypStream = new MemoryStream(enText))
            using (MemoryStream PlaiStream = new MemoryStream())
            {
                Byte[] Buffer = new Byte[ll2];
                int BlockSize = CrypStream.Read(Buffer, 0, ll2);

                while (BlockSize > 0)
                {
                    Byte[] ToDecrypt = new Byte[BlockSize];
                    Array.Copy(Buffer, 0, ToDecrypt, 0, BlockSize);

                    Byte[] Plaintext = rcp.Decrypt(ToDecrypt, false);
                    PlaiStream.Write(Plaintext, 0, Plaintext.Length);

                    BlockSize = CrypStream.Read(Buffer, 0, ll2);
                }

                res = Encoding.UTF8.GetString(PlaiStream.ToArray());
            }

            return res;
        }

        private static byte[] en(RSACryptoServiceProvider rcp, string planText)
        {

            var planTextData = Encoding.UTF8.GetBytes(planText);
            var ll = rcp.KeySize / 8 - 11;

            var enText = default(byte[]);
            using (MemoryStream PlaiStream = new MemoryStream(planTextData))
            using (MemoryStream CrypStream = new MemoryStream())
            {
                Byte[] Buffer = new Byte[ll];
                int BlockSize = PlaiStream.Read(Buffer, 0, ll);

                while (BlockSize > 0)
                {
                    Byte[] ToEncrypt = new Byte[BlockSize];
                    Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);

                    enText = rcp.Encrypt(ToEncrypt, false);
                    CrypStream.Write(enText, 0, enText.Length);

                    BlockSize = PlaiStream.Read(Buffer, 0, ll);
                }
                enText = CrypStream.ToArray();
                //return Convert.ToBase64String(CrypStream.ToArray(), Base64FormattingOptions.None);
            }
            return enText;
        }
    }
}
