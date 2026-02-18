-- CreateEnum
CREATE TYPE "ArtisanStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "artisanApprovedAt" TIMESTAMP(3),
ADD COLUMN     "artisanRejectionReason" TEXT,
ADD COLUMN     "artisanStatus" "ArtisanStatus";
