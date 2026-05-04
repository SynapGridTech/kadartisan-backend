-- AlterTable
ALTER TABLE "ServiceRequest" ADD COLUMN     "artisanId" INTEGER;

-- CreateIndex
CREATE INDEX "ServiceRequest_artisanId_idx" ON "ServiceRequest"("artisanId");

-- AddForeignKey
ALTER TABLE "ServiceRequest" ADD CONSTRAINT "ServiceRequest_artisanId_fkey" FOREIGN KEY ("artisanId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
