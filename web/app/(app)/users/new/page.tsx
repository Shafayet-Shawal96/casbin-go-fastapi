import { redirect } from "next/navigation";

import { CreateUserForm } from "@/components/forms";
import { can, requirePermission } from "@/lib/auth";
import { loadRoles } from "@/lib/roles";

export default async function NewUserPage() {
  const actor = await requirePermission("users", "create");
  if (!can(actor, "roles", "list")) redirect("/forbidden");
  const { roles } = await loadRoles();
  return <CreateUserForm roles={roles.filter((role) => role.assignable)} />;
}
