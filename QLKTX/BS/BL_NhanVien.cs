using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace QLKTX.BS
{
    public partial class BS_layer
    {
        public const string NoPermissionMessage = "Bạn không có quyền thực hiện thao tác này.";

        // Only an admin may add staff, or change another staff member's record, salary or manager.
        // An employee may edit only the contact fields of their own record.
        private bool CanUpdateNhanVien(string MaNV, int Luong, string MaNQL, ref string error)
        {
            if (Session.IsAdmin)
                return true;
            if (!Session.IsCurrentUser(MaNV))
            {
                error = NoPermissionMessage;
                return false;
            }

            string sql = "SELECT Luong, MaNQL FROM NhanVien WHERE MaNV = @MaNV";
            SqlParameter[] sqlParameters = new SqlParameter[] { new SqlParameter("MaNV", MaNV) };
            DataTable current = db.ExecuteQuery(sql, sqlParameters, CommandType.Text, ref error);
            if (current == null || current.Rows.Count != 1)
            {
                if (error == "") error = "Không tìm thấy nhân viên " + MaNV;
                return false;
            }

            bool sameLuong = current.Rows[0]["Luong"] != DBNull.Value && Convert.ToInt32(current.Rows[0]["Luong"]) == Luong;
            bool sameMaNQL = string.Equals(current.Rows[0]["MaNQL"].ToString().Trim(), (MaNQL ?? "").Trim(), StringComparison.OrdinalIgnoreCase);
            if (!sameLuong || !sameMaNQL)
            {
                error = "Chỉ quản trị viên mới được thay đổi lương và mã người quản lý.";
                return false;
            }
            return true;
        }

        public bool Insert(ref string error, string MaNV, string CMND, string HoTen, string SDT, string Email, string DiaChi, int Luong, string MaNQL, string avt)
        {
            if (!Session.IsAdmin)
            {
                error = NoPermissionMessage;
                return false;
            }
            string sql = "INSERT INTO NhanVien VALUES(@MaNV, @CMND, @HoTen, @SDT, @Email, @DiaChi,@Luong, @MaNQL, @AnhChanDung);";
            SqlParameter[] sqlParameters = new SqlParameter[]
            {
                new SqlParameter("MaNV", MaNV),
                new SqlParameter("CMND", CMND),
                new SqlParameter("HoTen", HoTen),
                new SqlParameter("SDT", SDT),
                new SqlParameter("Email", Email),
                new SqlParameter("DiaChi", DiaChi),
                new SqlParameter("Luong", Luong),
                new SqlParameter("MaNQL", MaNQL),
                new SqlParameter("AnhChanDung", avt)
            };
            return db.ExecuteNonQuery(sql, sqlParameters, System.Data.CommandType.Text, ref error);
        }

        public bool Update(ref string error, string MaNV, string CMND, string HoTen, string SDT, string Email, string DiaChi, int Luong, string MaNQL, string avt)
        {
            if (!CanUpdateNhanVien(MaNV, Luong, MaNQL, ref error))
                return false;
            string sql = "UPDATE NhanVien SET " +
                            "CMND = @CMND, " +
                            "HoTen = @HoTen, " +
                            "SDT = @SDT, " +
                            "Email = @Email, " +
                            "DiaChi = @DiaChi, " +
                            "Luong = @Luong, " +
                            "MaNQL = @MaNQL, " +
                            "AnhChanDung = @AnhChanDung " +
                         "WHERE MaNV = @MaNV;";
            SqlParameter[] sqlParameters = new SqlParameter[]
            {
                new SqlParameter("MaNV", MaNV),
                new SqlParameter("CMND", CMND),
                new SqlParameter("HoTen", HoTen),
                new SqlParameter("SDT", SDT),
                new SqlParameter("Email", Email),
                new SqlParameter("DiaChi", DiaChi),
                new SqlParameter("Luong", Luong),
                new SqlParameter("MaNQL", MaNQL),
                new SqlParameter("AnhChanDung", avt)
            };
            return db.ExecuteNonQuery(sql, sqlParameters, System.Data.CommandType.Text, ref error);
        }
    }
}
