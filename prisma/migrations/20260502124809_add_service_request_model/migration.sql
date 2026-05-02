-- CreateEnum
CREATE TYPE "ServiceRequestStatus" AS ENUM ('PENDING', 'MATCHED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED');

-- CreateTable
CREATE TABLE "ServiceRequest" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
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

-- CreateIndex
CREATE INDEX "ServiceRequest_state_skillRequired_status_idx" ON "ServiceRequest"("state", "skillRequired", "status");

-- CreateIndex
CREATE INDEX "ServiceRequest_userId_idx" ON "ServiceRequest"("userId");

-- AddForeignKey
ALTER TABLE "ServiceRequest" ADD CONSTRAINT "ServiceRequest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
