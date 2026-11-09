import { redirect } from "next/navigation";

import { CreateRoleForm } from "@/components/forms";
import { can, requirePermission } from "@/lib/auth";
import { loadRoles } from "@/lib/roles";

export default async function NewRolePage() {
  const actor = await requirePermission("roles", "create");
  if (!can(actor, "roles", "list")) redirect("/forbidden");
  const { grantable } = await loadRoles();
  return <CreateRoleForm grantable={grantable} />;
}
