-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'ARTISAN', 'ADMIN');

-- DropIndex
DROP INDEX "User_email_key";

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "role" "Role" NOT NULL DEFAULT 'USER',
ALTER COLUMN "isVerified" SET DEFAULT false;
