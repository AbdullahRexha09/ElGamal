using ElGamal.Models;
using ElGamal = ElGamal.Models.ElGamal;
using System;
using System.Text;
using System.Security.Cryptography;
using ElGamal.Extension;

namespace ElGamal
{
    class Program
    {
        static void Main(string[] args)
        {
           

            Console.WriteLine("Ju lutem shkruani tekstin per nenshkrim digjital:");
            string plainTextStr = Console.ReadLine();
            byte[] plaintext
            = Encoding.Default.GetBytes(plainTextStr);

            Models.ElGamal algoritem = new ElGamalManaged();
            algoritem.KeySize = 384;
            string xmlString = algoritem.ToXmlString(true);
            Console.WriteLine("\n{0}\n", xmlString);

            Models.ElGamal xSignAlg = new ElGamalManaged();
            xSignAlg.FromXmlString(algoritem.ToXmlString(true));
            byte[] signature = xSignAlg.Sign(plaintext);

            // signature forge
            byte[] eveSignature = new byte[signature.Length];
            for (int i = 0; i < signature.Length; i++) 
            {
                eveSignature[i] = 0xFF;
            }


            Models.ElGamal verifyAlg = new ElGamalManaged();
            verifyAlg.FromXmlString(algoritem.ToXmlString(false));
            Console.WriteLine("BASIC SIGNATURE: {0}",
             verifyAlg.VerifySignature(plaintext, eveSignature));


            //-----------------------------------------------
        }
    }
}
