using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace QLKTX.BS
{
    /// <summary>
    /// Salted PBKDF2-HMAC-SHA256 password hashing.
    /// Uses the native Windows CNG implementation (bcrypt.dll) because the managed
    /// Rfc2898DeriveBytes in .NET Framework 4.6.1 only supports SHA-1 and is very slow.
    /// Stored format: $pbkdf2-sha256$&lt;iterations&gt;$&lt;salt base64&gt;$&lt;hash base64&gt; (about 91 chars).
    /// </summary>
    public static class PasswordHasher
    {
        public const int Iterations = 600000;
        private const int SaltSize = 16;
        private const int HashSize = 32;
        private const string Prefix = "$pbkdf2-sha256$";

        // Verified when the user name does not exist, so the response time does not reveal valid user names.
        private static readonly Lazy<string> DummyHash = new Lazy<string>(() => Hash(Guid.NewGuid().ToString()));

        public static string Hash(string password)
        {
            if (password == null) throw new ArgumentNullException("password");
            byte[] salt = new byte[SaltSize];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }
            byte[] hash = Derive(password, salt, Iterations, HashSize);
            return Prefix + Iterations.ToString(CultureInfo.InvariantCulture) + "$"
                + Convert.ToBase64String(salt) + "$" + Convert.ToBase64String(hash);
        }

        public static bool IsHashed(string stored)
        {
            return stored != null && stored.StartsWith(Prefix, StringComparison.Ordinal);
        }

        /// <summary>
        /// Checks a password against a stored value. needsRehash is true when the password is correct
        /// but the stored value is legacy plaintext or uses fewer iterations than the current setting.
        /// </summary>
        public static bool Verify(string password, string stored, out bool needsRehash)
        {
            needsRehash = false;
            if (password == null || stored == null)
                return false;

            if (!IsHashed(stored))
            {
                // Legacy plaintext row (before hashing was added). The old SQL comparison ignored
                // trailing spaces, so do the same. The caller upgrades the row after a successful login.
                bool ok = FixedTimeEquals(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(stored.TrimEnd(' ')));
                needsRehash = ok;
                return ok;
            }

            string[] parts = stored.Substring(Prefix.Length).Split('$');
            int iterations;
            if (parts.Length != 3
                || !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out iterations)
                || iterations <= 0)
                return false;

            byte[] salt, expected;
            try
            {
                salt = Convert.FromBase64String(parts[1]);
                expected = Convert.FromBase64String(parts[2]);
            }
            catch (FormatException)
            {
                return false;
            }
            if (salt.Length == 0 || expected.Length == 0)
                return false;

            byte[] actual = Derive(password, salt, iterations, expected.Length);
            bool match = FixedTimeEquals(actual, expected);
            needsRehash = match && iterations < Iterations;
            return match;
        }

        /// <summary>Spends the same time as a real check. Call it when the user name was not found.</summary>
        public static void VerifyDummy(string password)
        {
            bool ignored;
            Verify(password ?? "", DummyHash.Value, out ignored);
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }

        public static byte[] Derive(string password, byte[] salt, int iterations, int length)
        {
            byte[] pwd = Encoding.UTF8.GetBytes(password);
            byte[] output = new byte[length];
            IntPtr hAlg = IntPtr.Zero;
            try
            {
                int status = BCryptOpenAlgorithmProvider(out hAlg, "SHA256", null, BCRYPT_ALG_HANDLE_HMAC_FLAG);
                if (status != 0)
                    throw new CryptographicException(status);
                status = BCryptDeriveKeyPBKDF2(hAlg, pwd, pwd.Length, salt, salt.Length,
                    (ulong)iterations, output, output.Length, 0);
                if (status != 0)
                    throw new CryptographicException(status);
                return output;
            }
            finally
            {
                Array.Clear(pwd, 0, pwd.Length);
                if (hAlg != IntPtr.Zero)
                    BCryptCloseAlgorithmProvider(hAlg, 0);
            }
        }

        private const uint BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008;

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId,
            string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDeriveKeyPBKDF2(IntPtr hPrf, byte[] pbPassword, int cbPassword,
            byte[] pbSalt, int cbSalt, ulong cIterations, byte[] pbDerivedKey, int cbDerivedKey, uint dwFlags);
    }
}
