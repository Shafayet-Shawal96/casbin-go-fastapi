import { notFound } from "next/navigation";

import { CompanyForm, DeactivateButton, InfoForm, RoleForm } from "@/components/forms";
import { UserDetails } from "@/components/UserDetails";
import { can, getToken, requirePermission } from "@/lib/auth";
import { parseId } from "@/lib/forward";
import { gatewayFetch } from "@/lib/gateway";
import { loadRoles } from "@/lib/roles";
import type { User } from "@/lib/types";

const SYSTEM_ADMIN = "system-admin";

type Props = { params: Promise<{ id: string }> };

export default async function UserPage({ params }: Props) {
  const actor = await requirePermission("users", "read");
  const id = parseId((await params).id);
  if (id === undefined) notFound();

  const res = await gatewayFetch(`/api/users/${id}`, { token: await getToken() });
  if (res.status === 404) notFound();
  if (!res.ok) throw new Error(`Could not load user (${res.status})`);
  const user: User = await res.json();

  const isSelf = actor.id === user.id;
  const targetIsProtected = user.role === SYSTEM_ADMIN && actor.role !== SYSTEM_ADMIN;
  const canEditInfo = can(actor, "user_info", "update", user.id) && !targetIsProtected;
  const canEditCompany = can(actor, "company_info", "update", user.id) && !targetIsProtected;
  const canAssign =
    can(actor, "user_role", "assign") &&
    can(actor, "roles", "list") &&
    !isSelf &&
    user.role !== SYSTEM_ADMIN;
  const canDeactivate = can(actor, "users", "deactivate") && !isSelf && user.is_active;

  const assignable = canAssign ? (await loadRoles()).roles.filter((r) => r.assignable) : [];

  return (
    <>
      <h1>{user.name}</h1>
      <UserDetails user={user} />
      {canEditInfo && <InfoForm user={user} />}
      {canEditCompany && <CompanyForm user={user} />}
      {canAssign && <RoleForm user={user} roles={assignable} />}
      {canDeactivate && <DeactivateButton userId={user.id} />}
    </>
  );
}
