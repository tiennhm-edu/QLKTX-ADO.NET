using System;
using System.Data;
using System.Data.SqlClient;
using QLKTX.DB;

namespace QLKTX.BS
{
    public class BL_DangNhap
    {
        public enum AccountType
        {
            Addmin,
            Employee,
        }

        DB_Main db = null;

        /// <summary>Set after a successful login when the password could not be upgraded to a hash.</summary>
        public string UpgradeWarning { get; private set; }

        public BL_DangNhap()
        {
            db = new DB_Main();
        }

        public bool Select(string TenDN, string MatKhau, ref string MaNV, ref AccountType accountType, ref string error)
        {
            UpgradeWarning = "";
            Session.End();

            string sql = "SELECT MaNV, MatKhau FROM DANGNHAP WHERE TenDN = @TenDN";
            SqlParameter[] sqlParameters = new SqlParameter[]
            {
                new SqlParameter("TenDN", TenDN)
            };
            DataTable table = db.ExecuteQuery(sql, sqlParameters, CommandType.Text, ref error);
            if (table == null || table.Rows.Count == 0)
            {
                // Spend the same time as a real check so the response time does not reveal valid user names.
                PasswordHasher.VerifyDummy(MatKhau);
                return false;
            }

            string stored = table.Rows[0]["MatKhau"].ToString();
            bool needsRehash;
            if (!PasswordHasher.Verify(MatKhau, stored, out needsRehash))
                return false;

            if (needsRehash)
                UpgradePassword(TenDN, stored, MatKhau);

            MaNV = table.Rows[0]["MaNV"].ToString().Trim();
            accountType = GetAccountType(MaNV);
            Session.Start(MaNV, accountType);
            return true;
        }

        // Replaces a legacy plaintext (or weaker) value with a PBKDF2 hash. Login still succeeds if this
        // fails, for example when DB/Migrations/001_hash_passwords.sql has not been run yet.
        private void UpgradePassword(string TenDN, string oldValue, string MatKhau)
        {
            string err = "";
            string sql = "UPDATE DANGNHAP SET MatKhau = @NewHash WHERE TenDN = @TenDN AND MatKhau = @OldValue";
            SqlParameter[] sqlParameters = new SqlParameter[]
            {
                new SqlParameter("NewHash", PasswordHasher.Hash(MatKhau)),
                new SqlParameter("TenDN", TenDN),
                new SqlParameter("OldValue", oldValue)
            };
            try
            {
                if (!db.ExecuteNonQuery(sql, sqlParameters, CommandType.Text, ref err))
                    UpgradeWarning = "Không thể mã hóa mật khẩu trong CSDL. Hãy chạy DB/Migrations/001_hash_passwords.sql.\n" + err;
            }
            catch (Exception ex)
            {
                UpgradeWarning = "Không thể mã hóa mật khẩu trong CSDL.\n" + ex.Message;
            }
        }

        // Admin = staff member with no manager (MaNQL is NULL or empty). Uses an exact match on MaNV:
        // the generic LIKE search could return another employee whose code contains this one (NV1 / NV10).
        // Any lookup problem falls back to the lower privilege.
        private AccountType GetAccountType(string MaNV)
        {
            string err = "";
            string sql = "SELECT MaNQL FROM NhanVien WHERE MaNV = @MaNV";
            SqlParameter[] sqlParameters = new SqlParameter[]
            {
                new SqlParameter("MaNV", MaNV)
            };
            DataTable table = db.ExecuteQuery(sql, sqlParameters, CommandType.Text, ref err);
            if (err != "" || table == null || table.Rows.Count != 1)
                return AccountType.Employee;

            string maNQL = table.Rows[0]["MaNQL"].ToString().Trim();
            return maNQL == "" ? AccountType.Addmin : AccountType.Employee;
        }
    }
}
