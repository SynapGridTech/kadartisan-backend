-- Add customer location/address fields (collected on the registration
-- location-setup screen) plus an updatedAt column to CustomerProfile.
ALTER TABLE "CustomerProfile" ADD COLUMN "location" TEXT;
ALTER TABLE "CustomerProfile" ADD COLUMN "state" TEXT;
ALTER TABLE "CustomerProfile" ADD COLUMN "lga" TEXT;
ALTER TABLE "CustomerProfile" ADD COLUMN "address" TEXT;
ALTER TABLE "CustomerProfile" ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
