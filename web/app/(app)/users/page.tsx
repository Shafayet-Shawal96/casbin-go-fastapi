import Link from "next/link";

import { can, getToken, requirePermission } from "@/lib/auth";
import { gatewayFetch } from "@/lib/gateway";
import type { UserList } from "@/lib/types";

const PAGE_SIZE = 20;

type Props = { searchParams: Promise<{ offset?: string }> };

export default async function UsersPage({ searchParams }: Props) {
  const actor = await requirePermission("users", "list");
  const requested = Number((await searchParams).offset ?? 0);
  const offset = Number.isInteger(requested) && requested > 0 ? requested : 0;

  const res = await gatewayFetch(`/api/users?limit=${PAGE_SIZE}&offset=${offset}`, {
    token: await getToken(),
  });
  if (!res.ok) throw new Error(`Could not load users (${res.status})`);
  const data: UserList = await res.json();
  const canRead = can(actor, "users", "read");

  return (
    <>
      <div className="toolbar">
        <h1>Users</h1>
        {can(actor, "users", "create") && <Link href="/users/new">New user</Link>}
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Company</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((user) => (
              <tr key={user.id}>
                <td>{canRead ? <Link href={`/users/${user.id}`}>{user.name}</Link> : user.name}</td>
                <td>{user.email}</td>
                <td>{user.role}</td>
                <td>{user.company_name || "-"}</td>
                <td>{user.is_active ? "Active" : "Deactivated"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pager">
        {offset > 0 && <Link href={`/users?offset=${Math.max(0, offset - PAGE_SIZE)}`}>Previous</Link>}
        {offset + PAGE_SIZE < data.total && <Link href={`/users?offset=${offset + PAGE_SIZE}`}>Next</Link>}
      </div>
    </>
  );
}
