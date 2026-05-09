-- AlterTable
ALTER TABLE "User" ADD COLUMN     "banReason" TEXT,
ADD COLUMN     "bannedAt" TIMESTAMP(3),
ADD COLUMN     "suspendedUntil" TIMESTAMP(3),
ADD COLUMN     "suspensionReason" TEXT;
