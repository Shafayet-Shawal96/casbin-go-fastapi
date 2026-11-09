import type { User } from "@/lib/types";

export function UserDetails({ user }: { user: User }) {
  const rows: [string, string | null][] = [
    ["Email", user.email],
    ["Name", user.name],
    ["Phone", user.phone],
    ["Role", user.role],
    ["Status", user.is_active ? "Active" : "Deactivated"],
    ["Company", user.company_name],
    ["Department", user.department],
    ["Designation", user.designation],
  ];
  return (
    <div className="card">
      <dl>
        {rows.map(([label, value]) => (
          <div key={label} style={{ display: "contents" }}>
            <dt>{label}</dt>
            <dd>{value || "-"}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
