import Link from "next/link";
import type { ReactNode } from "react";

import { LogoutButton } from "@/components/forms";
import { can, requireUser } from "@/lib/auth";

export default async function AppLayout({ children }: { children: ReactNode }) {
  const user = await requireUser();
  return (
    <>
      <nav>
        <Link href="/me">My profile</Link>
        {can(user, "users", "list") && <Link href="/users">Users</Link>}
        {can(user, "roles", "create") && <Link href="/roles/new">New role</Link>}
        <span className="spacer" />
        <span className="who">
          {user.name} ({user.role})
        </span>
        <LogoutButton />
      </nav>
      <main>{children}</main>
    </>
  );
}
