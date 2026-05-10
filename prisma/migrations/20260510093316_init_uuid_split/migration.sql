-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'ARTISAN', 'ADMIN');

-- CreateEnum
CREATE TYPE "OtpChannel" AS ENUM ('PHONE', 'EMAIL', 'WHATSAPP');

-- CreateEnum
CREATE TYPE "ArtisanStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

-- CreateEnum
CREATE TYPE "ServiceRequestStatus" AS ENUM ('PENDING', 'MATCHED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "AppealStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

-- CreateTable
CREATE TABLE "User" (
    "id" UUID NOT NULL,
    "fullName" TEXT NOT NULL,
    "phoneNumber" TEXT NOT NULL,
    "email" TEXT,
    "password" TEXT NOT NULL,
    "isVerified" BOOLEAN NOT NULL DEFAULT false,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "failedLoginAttempts" INTEGER NOT NULL DEFAULT 0,
    "lockUntil" TIMESTAMP(3),
    "refreshToken" TEXT,
    "suspendedUntil" TIMESTAMP(3),
    "suspensionReason" TEXT,
    "bannedAt" TIMESTAMP(3),
    "banReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AdminProfile" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AdminProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CustomerProfile" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CustomerProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ArtisanProfile" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "state" TEXT NOT NULL,
    "lga" TEXT,
    "workshopAddress" TEXT,
    "artisanStatus" "ArtisanStatus" NOT NULL DEFAULT 'PENDING',
    "artisanApprovedAt" TIMESTAMP(3),
    "artisanRejectionReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ArtisanProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Skill" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "category" TEXT,

    CONSTRAINT "Skill_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ArtisanSkill" (
    "id" UUID NOT NULL,
    "artisanId" UUID NOT NULL,
    "skillId" UUID NOT NULL,

    CONSTRAINT "ArtisanSkill_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ServiceRequest" (
    "id" UUID NOT NULL,
    "customerId" UUID NOT NULL,
    "artisanId" UUID,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "image" TEXT,
    "state" TEXT NOT NULL,
    "lga" TEXT,
    "skillRequired" TEXT NOT NULL,
    "budget" DOUBLE PRECISION,
    "urgency" TEXT,
    "contactInfo" TEXT,
    "status" "ServiceRequestStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ServiceRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Appeal" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "reason" TEXT NOT NULL,
    "status" "AppealStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Appeal_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Otp" (
    "id" UUID NOT NULL,
    "identifier" TEXT NOT NULL,
    "channel" "OtpChannel" NOT NULL,
    "code" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "isUsed" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" UUID,

    CONSTRAINT "Otp_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_phoneNumber_key" ON "User"("phoneNumber");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "AdminProfile_userId_key" ON "AdminProfile"("userId");

-- CreateIndex
CREATE INDEX "AdminProfile_userId_idx" ON "AdminProfile"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "CustomerProfile_userId_key" ON "CustomerProfile"("userId");

-- CreateIndex
CREATE INDEX "CustomerProfile_userId_idx" ON "CustomerProfile"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "ArtisanProfile_userId_key" ON "ArtisanProfile"("userId");

-- CreateIndex
CREATE INDEX "ArtisanProfile_userId_idx" ON "ArtisanProfile"("userId");

-- CreateIndex
CREATE INDEX "ArtisanProfile_artisanStatus_idx" ON "ArtisanProfile"("artisanStatus");

-- CreateIndex
CREATE UNIQUE INDEX "Skill_name_key" ON "Skill"("name");

-- CreateIndex
CREATE INDEX "Skill_name_idx" ON "Skill"("name");

-- CreateIndex
CREATE INDEX "ArtisanSkill_artisanId_idx" ON "ArtisanSkill"("artisanId");

-- CreateIndex
CREATE INDEX "ArtisanSkill_skillId_idx" ON "ArtisanSkill"("skillId");

-- CreateIndex
CREATE UNIQUE INDEX "ArtisanSkill_artisanId_skillId_key" ON "ArtisanSkill"("artisanId", "skillId");

-- CreateIndex
CREATE INDEX "ServiceRequest_state_skillRequired_status_idx" ON "ServiceRequest"("state", "skillRequired", "status");

-- CreateIndex
CREATE INDEX "ServiceRequest_customerId_idx" ON "ServiceRequest"("customerId");

-- CreateIndex
CREATE INDEX "ServiceRequest_artisanId_idx" ON "ServiceRequest"("artisanId");

-- CreateIndex
CREATE UNIQUE INDEX "Appeal_userId_key" ON "Appeal"("userId");

-- CreateIndex
CREATE INDEX "Appeal_userId_idx" ON "Appeal"("userId");

-- CreateIndex
CREATE INDEX "Appeal_status_idx" ON "Appeal"("status");

-- CreateIndex
CREATE INDEX "Otp_identifier_idx" ON "Otp"("identifier");

-- CreateIndex
CREATE INDEX "Otp_userId_idx" ON "Otp"("userId");

-- AddForeignKey
ALTER TABLE "AdminProfile" ADD CONSTRAINT "AdminProfile_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CustomerProfile" ADD CONSTRAINT "CustomerProfile_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArtisanProfile" ADD CONSTRAINT "ArtisanProfile_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArtisanSkill" ADD CONSTRAINT "ArtisanSkill_artisanId_fkey" FOREIGN KEY ("artisanId") REFERENCES "ArtisanProfile"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArtisanSkill" ADD CONSTRAINT "ArtisanSkill_skillId_fkey" FOREIGN KEY ("skillId") REFERENCES "Skill"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ServiceRequest" ADD CONSTRAINT "ServiceRequest_customerId_fkey" FOREIGN KEY ("customerId") REFERENCES "CustomerProfile"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ServiceRequest" ADD CONSTRAINT "ServiceRequest_artisanId_fkey" FOREIGN KEY ("artisanId") REFERENCES "ArtisanProfile"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Appeal" ADD CONSTRAINT "Appeal_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Otp" ADD CONSTRAINT "Otp_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
