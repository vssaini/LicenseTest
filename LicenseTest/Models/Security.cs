using System;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Configuration;
using Microsoft.Win32;
using Portable.Licensing;
using Portable.Licensing.Security.Cryptography;
using Portable.Licensing.Validation;
using Resources;

namespace LicenseTest.Models
{
    /// <summary>
    /// This class is used to provide features as encrypt, decrypt, validate license and save dates in registry.
    /// </summary>
    public static class Security
    {
        // Global variables
        private const string PassPhrase = "ADPhonebook Critical Security";
        static readonly string LicensePath = HttpContext.Current.Server.MapPath(Home.TrialLicensePath);
        private static readonly string CurrentDate = DateTime.Now.ToString("dd-MM-yyyy");

        #region License Properties

        /// <summary>
        /// Validate license file and return true if valid.
        /// </summary>
        /// <returns>Return true if valid license file provided.</returns>
        public static bool IsValidLicense
        {
            get
            {
                bool isValid;
                try
                {
                    // Read license file
                    var licenseFile = HttpContext.Current.Server.MapPath(Home.LicensePath);
                    var license = License.Load(File.ReadAllText(licenseFile));

                    var validationFailures = license.Validate().Signature(Home.LicensePublicKey)
                        .When(lic => lic.Type.Equals(LicenseType.Standard))
                        .AssertValidLicense();

                    isValid = !validationFailures.Any();
                }
                catch (Exception)
                {
                    isValid = false;
                }

                return isValid;
            }
        }

        /// <summary>
        /// Check if website is still in trial mode (30 days limit)
        /// </summary>
        public static bool IsInThirtyDayTrialMode
        {
            get
            {
                bool isInTrialMode;

                try
                {
                    // 1. Get first use date key
                    var fudKey = ConfigurationManager.AppSettings["FUD"];
                    var publicKey = ConfigurationManager.AppSettings["PublicKey"];

                    if (!string.IsNullOrEmpty(fudKey))
                        fudKey = Decrypt(fudKey);

                    // 2.1. If first use date key and public key not exists, then create it
                    if (string.IsNullOrEmpty(fudKey) && string.IsNullOrEmpty(publicKey))
                    {
                        isInTrialMode = CreateLicenseFile();
                    }
                    else
                    {
                        isInTrialMode = IsValidTrialLicense();

                        // Save last date use key
                        var ludKey = ConfigurationManager.AppSettings["LUD"];

                        if (string.IsNullOrEmpty(ludKey))
                        {
                            SaveToConfig("LUD", Encrypt(CurrentDate));
                        }
                        else
                        {
                            // If system date less than last used date, mark trial expired
                            var systemDate = DateTime.ParseExact(CurrentDate, "dd-MM-yyyy", CultureInfo.InvariantCulture);
                            var lastUseDate = DateTime.ParseExact(Decrypt(ludKey), "dd-MM-yyyy", CultureInfo.InvariantCulture);

                            if (systemDate < lastUseDate)
                            {
                                isInTrialMode = false;
                            }
                            else
                            {
                                SaveToConfig("LUD", Encrypt(CurrentDate));
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    isInTrialMode = false;
                }

                return isInTrialMode;
            }
        }

        #endregion

        #region Encrypt or Decrypt

        // This constant string is used as a "salt" value.
        // This size of the IV (in bytes) must = (keysize / 8).  Default keysize is 256, so the IV must be
        // 32 bytes long.  Using a 16 character string here gives us 32 bytes when converted to a byte array.
        private static readonly byte[] InitVectorBytes = Encoding.ASCII.GetBytes("tu89geji340t89u2");

        // This constant is used to determine the keysize of the encryption algorithm.
        private const int Keysize = 256;

        /// <summary>
        /// Encrypt plain text and return cipher text.
        /// </summary>
        public static string Encrypt(string plainText)
        {
            string cipherText;

            try
            {
                var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

                using (var password = new Rfc2898DeriveBytes(PassPhrase, InitVectorBytes))
                {
                    var keyBytes = password.GetBytes(Keysize / 8);
                    using (var symmetricKey = new RijndaelManaged())
                    {
                        symmetricKey.Mode = CipherMode.CBC;
                        using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, InitVectorBytes))
                        {
                            using (var memoryStream = new MemoryStream())
                            {
                                using (
                                    var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)
                                    )
                                {
                                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                    cryptoStream.FlushFinalBlock();
                                    var cipherTextBytes = memoryStream.ToArray();
                                    cipherText = Convert.ToBase64String(cipherTextBytes);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                cipherText = null;
            }

            return cipherText;
        }

        /// <summary>
        /// Decrypt cipher text and return plain text.
        /// </summary>
        public static string Decrypt(string cipherText)
        {
            string plainText;

            try
            {
                var cipherTextBytes = Convert.FromBase64String(cipherText);
                using (var password = new Rfc2898DeriveBytes(PassPhrase, InitVectorBytes))
                {
                    var keyBytes = password.GetBytes(Keysize / 8);
                    using (var symmetricKey = new RijndaelManaged())
                    {
                        symmetricKey.Mode = CipherMode.CBC;
                        using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, InitVectorBytes))
                        {
                            using (var memoryStream = new MemoryStream(cipherTextBytes))
                            {
                                using (
                                    var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                                {
                                    var plainTextBytes = new byte[cipherTextBytes.Length];
                                    var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                    plainText = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                plainText = null;
            }

            return plainText;
        }

        #endregion

        #region License - For trial limit of 30 days

        /// <summary>
        /// Create trial license file and preserve some values to web.config too.
        /// </summary>
        private static bool CreateLicenseFile()
        {
            bool licenseCreated;

            try
            {
                // Generate keys
                var keyGenerator = KeyGenerator.Create();
                var keyPair = keyGenerator.GenerateKeyPair();
                var privateKey = keyPair.ToEncryptedPrivateKeyString(PassPhrase);
                var publicKey = keyPair.ToPublicKeyString();

                // Save license file
                licenseCreated = GenerateLicense(privateKey);
                if (licenseCreated)
                {
                    // Save public key to web.config
                    SaveToConfig("PublicKey", publicKey);

                    // Save First use date
                    SaveToConfig("FUD", Encrypt(CurrentDate));
                }
            }
            catch (Exception)
            {
                // Exception will raise when user had not granted permission to NETWORK SERVICE
                // for creating license file to App_Data
                licenseCreated = false;
            }

            return licenseCreated;
        }

        /// <summary>
        /// Generate and save trial license file
        /// </summary>
        /// <returns></returns>
        public static bool GenerateLicense(string privateKey)
        {
            // Create license
            var license = License.New()
                .WithUniqueIdentifier(Guid.NewGuid())
                .As(LicenseType.Trial)
                .ExpiresAt(DateTime.Now.AddDays(30))
                .CreateAndSignWithPrivateKey(privateKey, PassPhrase);

            // Save license content into license file
            File.WriteAllText(LicensePath, license.ToString(), Encoding.UTF8);
            return true;
        }

        /// <summary>
        /// Modify existing keys values and save them
        /// </summary>
        /// <param name="key">The name of key</param>
        /// <param name="value">The value to be written</param>
        private static void SaveToConfig(string key, string value)
        {
            var config = WebConfigurationManager.OpenWebConfiguration("~");
            config.AppSettings.Settings[key].Value = value;
            config.Save();
        }

        /// <summary>
        /// Check if license is valid or not.
        /// </summary>
        /// <returns>Return true if license is valid.</returns>
        public static bool IsValidTrialLicense()
        {
            bool isValid;
            try
            {
                var licenseContent = File.ReadAllText(LicensePath);
                var license = License.Load(licenseContent);
                var publicKey = ConfigurationManager.AppSettings["PublicKey"];

                var validationFailures = license.Validate().ExpirationDate()
                    .When(lic => lic.Type == LicenseType.Trial)
                    .And()
                    .Signature(publicKey)
                    .AssertValidLicense();

                isValid = !validationFailures.Any();
            }
            catch (Exception)
            {
                isValid = false;
            }

            return isValid;
        }

        #endregion

        #region Get Application Installed Date

        /// <summary>
        /// Get installed date from registry for application
        /// </summary>
        /// <param name="appName">Name of application or website</param>
        /// <returns>Return installed date</returns>
        public static string GetApplicationDate(string appName)
        {
            string installDate = null;

            // Search in: CurrentUser
            var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            if (key != null)
            {
                installDate = GetDate(key, appName);
            }

            // Search in: LocalMachine_32
            key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            if (key != null)
            {
                installDate = GetDate(key, appName);
            }

            // Search in: LocalMachine_64
            key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall");
            if (key != null)
            {
                installDate = GetDate(key, appName);
            }

            if (string.IsNullOrEmpty(installDate)) return installDate;

            var year = installDate.Substring(0, 4);
            var month = installDate.Substring(4, 2);
            var date = installDate.Substring(6, 2);

            return string.Format("{0}-{1}-{2}", year, month, date);
        }

        public static string GetDate(RegistryKey key, string appName)
        {
            string installDate = null;

            var regKey = key;
            foreach (var subkey in from subkey in key.GetSubKeyNames().Select(regKey.OpenSubKey)
                .Where(subkey => subkey != null)
                                   let displayName = Convert.ToString(subkey.GetValue("DisplayName"))
                                   where appName.Equals(displayName, StringComparison.OrdinalIgnoreCase)
                                   select subkey)
            {
                installDate = Convert.ToString(subkey.GetValue("InstallDate"));
            }

            return installDate;
        }

        #endregion
    }
}