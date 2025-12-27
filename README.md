
---

## 🧩 kadartisan-backend 

```md
# KadArtisan Backend

This repository contains the backend services and APIs that power the KadArtisan platform.

KadArtisan connects verified local artisans with customers, providing discovery, booking, trust, and administrative capabilities.

---

## 🎯 Purpose

The backend is responsible for:
- User authentication & authorization
- Artisan onboarding and verification
- Search and discovery logic
- Booking and service requests
- Reviews and ratings
- Admin moderation and analytics
- Scalable and secure data management

---

## 🧑‍💼 User Roles

- **Artisan**
- **Customer**
- **Administrator**
- **Partner / NGO (future phase)**

---

## 🧱 Tech Stack (Recommended)

- **Framework:** NestJS
- **Language:** TypeScript
- **Database:** PostgreSQL / MongoDB
- **ORM/ODM:** TypeORM / Prisma / Mongoose
- **Auth:** JWT + Refresh Tokens
- **Validation:** class-validator
- **API Style:** REST (GraphQL optional later)
- **File Storage:** Cloudinary / S3
- **Notifications:** Email / WhatsApp integration
- **Deployment:** Docker-ready

---

## 📐 Core Modules (MVP)

- Auth Module
- User Module
- Artisan Module
- Booking Module
- Review & Rating Module
- Admin Module
- Media Upload Module

---

## 🗂️ Project Structure (Example)

```text
src/
├── auth/
├── users/
├── artisans/
├── bookings/
├── reviews/
├── admin/
├── common/
├── database/
└── main.ts
