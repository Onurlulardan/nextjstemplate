-- CreateTable
CREATE TABLE "RoleMember" (
    "id" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RoleMember_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "RoleMember_userId_idx" ON "RoleMember"("userId");

-- CreateIndex
CREATE INDEX "RoleMember_roleId_idx" ON "RoleMember"("roleId");

-- CreateIndex
CREATE UNIQUE INDEX "RoleMember_roleId_userId_key" ON "RoleMember"("roleId", "userId");

-- AddForeignKey
ALTER TABLE "RoleMember" ADD CONSTRAINT "RoleMember_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "Role"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RoleMember" ADD CONSTRAINT "RoleMember_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
