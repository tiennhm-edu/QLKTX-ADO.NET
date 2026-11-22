-- Issue #3: store passwords as PBKDF2 hashes instead of plaintext.
-- A hash looks like $pbkdf2-sha256$600000$<salt>$<hash> (about 91 characters),
-- so MatKhau must be wider than VARCHAR(50).
--
-- Run this once on the QUANLYKTX database BEFORE deploying the new build.
-- Existing plaintext passwords keep working: each one is replaced by a hash
-- the next time that user logs in successfully.
--
-- To find accounts that have not been upgraded yet:
--   SELECT TenDN FROM DANGNHAP WHERE MatKhau NOT LIKE '$pbkdf2-sha256$%';
-- New accounts: insert the hash produced by QLKTX.BS.PasswordHasher.Hash(password),
-- or insert a plaintext password and let the first login upgrade it.

USE QUANLYKTX;
GO

ALTER TABLE DANGNHAP
    ALTER COLUMN MatKhau VARCHAR(256) COLLATE SQL_Latin1_General_CP1_CS_AS NOT NULL;
GO
