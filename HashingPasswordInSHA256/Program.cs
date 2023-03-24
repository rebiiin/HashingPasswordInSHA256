using System.Security.Cryptography;
using System.Text;

namespace HashingPasswordInSHA256
{
    internal class Program
    {
        static void Main(string[] args)
        {
            byte[] salt = new byte[16];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);


            ///password
            string password = "myPassword123";
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // Combine the password and salt bytes

            byte[] saltedPasswordBytes = new byte[passwordBytes.Length + salt.Length];

            Array.Copy(passwordBytes, saltedPasswordBytes,passwordBytes.Length);
            Array.Copy(salt, 0, saltedPasswordBytes,passwordBytes.Length,salt.Length);

            // Hash the salted password using  SHA256   


            string hashString = string.Empty;
            string saltString = string.Empty;


            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(saltedPasswordBytes);


                //convert the hash and slat to base64 strings for storage

                 hashString = Convert.ToBase64String(hashBytes);
                 saltString = Convert.ToBase64String(salt);


                Console.WriteLine("Hash: " + hashString);
                Console.WriteLine("Salt: " + saltString);
            }


            //verify the plain password

            string passwordInput = "myPassword123";


          var result =  isVerifyHash(passwordInput, hashString,saltString);



            if(result )
            {
                Console.WriteLine("Password is correct");
            }
            else
            {
                Console.WriteLine("Password is incorrect");
            }




            Console.ReadKey();

        }


        private static bool isVerifyHash(string plainText,string hashedText,string saltedText)
        {

            bool isVerify;

            // Convert the password and stored salt to bytes
            byte[] passwordBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] saltBytes = Convert.FromBase64String(saltedText);

            // Combine the password and salt bytes
            byte[] saltedPasswordBytes = new byte[passwordBytes.Length + saltBytes.Length];
            Array.Copy(passwordBytes, saltedPasswordBytes, passwordBytes.Length);
            Array.Copy(saltBytes, 0, saltedPasswordBytes, passwordBytes.Length, saltBytes.Length);

            using (SHA256 sha256 = SHA256.Create())

            {
                byte[] hashBytes = sha256.ComputeHash(saltedPasswordBytes);

                 
                // Convert the hash to a base64 string for comparison with the stored hash
                string hashString = Convert.ToBase64String(hashBytes);

                if (hashString == hashedText)
                {
                    isVerify = true;

                }
                else 
                {
                    isVerify = false;
                }


            }


            return isVerify;


        }


    }
}