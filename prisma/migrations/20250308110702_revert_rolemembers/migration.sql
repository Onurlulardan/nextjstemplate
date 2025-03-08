/*
  Warnings:

  - You are about to drop the `RoleMember` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "RoleMember" DROP CONSTRAINT "RoleMember_roleId_fkey";

-- DropForeignKey
ALTER TABLE "RoleMember" DROP CONSTRAINT "RoleMember_userId_fkey";

-- DropTable
DROP TABLE "RoleMember";
