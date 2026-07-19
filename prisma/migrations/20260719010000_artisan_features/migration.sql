-- Artisan features: saved requests, profile views, headline, scheduledAt, conversations & messaging

-- ArtisanProfile: display headline + profile view counter
ALTER TABLE "ArtisanProfile" ADD COLUMN "headline" TEXT;
ALTER TABLE "ArtisanProfile" ADD COLUMN "profileViews" INTEGER NOT NULL DEFAULT 0;

-- ServiceRequest: preferred/scheduled time
ALTER TABLE "ServiceRequest" ADD COLUMN "scheduledAt" TIMESTAMP(3);

-- ---------- SavedRequest ----------
CREATE TABLE "SavedRequest" (
    "id" UUID NOT NULL,
    "artisanId" UUID NOT NULL,
    "requestId" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SavedRequest_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "SavedRequest_artisanId_requestId_key" ON "SavedRequest"("artisanId", "requestId");
CREATE INDEX "SavedRequest_artisanId_idx" ON "SavedRequest"("artisanId");
CREATE INDEX "SavedRequest_requestId_idx" ON "SavedRequest"("requestId");

ALTER TABLE "SavedRequest" ADD CONSTRAINT "SavedRequest_artisanId_fkey" FOREIGN KEY ("artisanId") REFERENCES "ArtisanProfile"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SavedRequest" ADD CONSTRAINT "SavedRequest_requestId_fkey" FOREIGN KEY ("requestId") REFERENCES "ServiceRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------- Conversation ----------
CREATE TABLE "Conversation" (
    "id" UUID NOT NULL,
    "customerUserId" UUID NOT NULL,
    "artisanUserId" UUID NOT NULL,
    "requestId" UUID,
    "lastMessageAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Conversation_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "Conversation_customerUserId_artisanUserId_requestId_key" ON "Conversation"("customerUserId", "artisanUserId", "requestId");
CREATE INDEX "Conversation_customerUserId_idx" ON "Conversation"("customerUserId");
CREATE INDEX "Conversation_artisanUserId_idx" ON "Conversation"("artisanUserId");
CREATE INDEX "Conversation_lastMessageAt_idx" ON "Conversation"("lastMessageAt");

ALTER TABLE "Conversation" ADD CONSTRAINT "Conversation_customerUserId_fkey" FOREIGN KEY ("customerUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Conversation" ADD CONSTRAINT "Conversation_artisanUserId_fkey" FOREIGN KEY ("artisanUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Conversation" ADD CONSTRAINT "Conversation_requestId_fkey" FOREIGN KEY ("requestId") REFERENCES "ServiceRequest"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- ---------- Message ----------
CREATE TABLE "Message" (
    "id" UUID NOT NULL,
    "conversationId" UUID NOT NULL,
    "senderUserId" UUID NOT NULL,
    "body" TEXT NOT NULL,
    "readAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Message_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "Message_conversationId_idx" ON "Message"("conversationId");
CREATE INDEX "Message_senderUserId_idx" ON "Message"("senderUserId");

ALTER TABLE "Message" ADD CONSTRAINT "Message_conversationId_fkey" FOREIGN KEY ("conversationId") REFERENCES "Conversation"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Message" ADD CONSTRAINT "Message_senderUserId_fkey" FOREIGN KEY ("senderUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
