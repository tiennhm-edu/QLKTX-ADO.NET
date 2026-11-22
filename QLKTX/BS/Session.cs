namespace QLKTX.BS
{
    /// <summary>
    /// The signed-in user. Set only by BL_DangNhap after a successful login, and used by the
    /// business layer to enforce role checks (the UI checks are only for convenience).
    /// </summary>
    public static class Session
    {
        public static string MaNV { get; private set; }
        public static BL_DangNhap.AccountType AccountType { get; private set; }
        public static bool IsLoggedIn { get; private set; }

        public static bool IsAdmin
        {
            get { return IsLoggedIn && AccountType == BL_DangNhap.AccountType.Addmin; }
        }

        public static bool IsCurrentUser(string maNV)
        {
            return IsLoggedIn && maNV != null && string.Equals(MaNV, maNV.Trim(), System.StringComparison.OrdinalIgnoreCase);
        }

        internal static void Start(string maNV, BL_DangNhap.AccountType accountType)
        {
            MaNV = maNV.Trim();
            AccountType = accountType;
            IsLoggedIn = true;
        }

        public static void End()
        {
            MaNV = null;
            AccountType = BL_DangNhap.AccountType.Employee;
            IsLoggedIn = false;
        }
    }
}
