"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

import { sendJson } from "@/lib/client";
import type { Permission, RoleInfo, User } from "@/lib/types";

type Status = { kind: "error" | "success"; text: string } | null;

function StatusLine({ status }: { status: Status }) {
  if (!status) return null;
  return <p className={status.kind}>{status.text}</p>;
}

type Field = {
  name: string;
  label: string;
  type?: string;
  required?: boolean;
  value?: string | null;
};

type JsonFormProps = {
  url: string;
  method: string;
  fields: Field[];
  submitLabel: string;
  title?: string;
  onSuccess?: (data: unknown) => void;
};

/** Sends the fields as JSON. Optional fields left blank are sent as null. */
function JsonForm({ url, method, fields, submitLabel, title, onSuccess }: JsonFormProps) {
  const router = useRouter();
  const [status, setStatus] = useState<Status>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const body = Object.fromEntries(
      fields.map((field) => {
        const value = String(data.get(field.name) ?? "");
        return [field.name, value === "" && !field.required ? null : value];
      }),
    );

    setBusy(true);
    const result = await sendJson(url, method, body);
    setBusy(false);
    if (!result.ok) {
      setStatus({ kind: "error", text: result.message });
      return;
    }
    setStatus({ kind: "success", text: "Saved" });
    if (onSuccess) onSuccess(result.data);
    else router.refresh();
  }

  return (
    <form onSubmit={submit} className="card">
      {title && <h2>{title}</h2>}
      {fields.map((field) => (
        <label key={field.name}>
          {field.label}
          <input
            name={field.name}
            type={field.type ?? "text"}
            required={field.required}
            defaultValue={field.value ?? ""}
          />
        </label>
      ))}
      <button disabled={busy}>{busy ? "Working..." : submitLabel}</button>
      <StatusLine status={status} />
    </form>
  );
}

export function LoginForm() {
  return (
    <JsonForm
      url="/api/auth/login"
      method="POST"
      title="Sign in"
      submitLabel="Sign in"
      fields={[
        { name: "email", label: "Email", type: "email", required: true },
        { name: "password", label: "Password", type: "password", required: true },
      ]}
      onSuccess={() => window.location.assign("/me")}
    />
  );
}

export function LogoutButton() {
  async function logout() {
    await sendJson("/api/auth/logout", "POST");
    window.location.assign("/login");
  }
  return (
    <button className="link" onClick={logout}>
      Sign out
    </button>
  );
}

export function InfoForm({ user }: { user: User }) {
  return (
    <JsonForm
      url={`/api/users/${user.id}/info`}
      method="PATCH"
      title="User info"
      submitLabel="Save user info"
      fields={[
        { name: "name", label: "Name", required: true, value: user.name },
        { name: "phone", label: "Phone", value: user.phone },
      ]}
    />
  );
}

export function CompanyForm({ user }: { user: User }) {
  return (
    <JsonForm
      url={`/api/users/${user.id}/company`}
      method="PATCH"
      title="Company info"
      submitLabel="Save company info"
      fields={[
        { name: "company_name", label: "Company", value: user.company_name },
        { name: "department", label: "Department", value: user.department },
        { name: "designation", label: "Designation", value: user.designation },
      ]}
    />
  );
}

function RoleSelect({ roles, value }: { roles: RoleInfo[]; value?: string }) {
  return (
    <label>
      Role
      <select name="role" required defaultValue={value ?? ""}>
        <option value="" disabled>
          Select a role
        </option>
        {roles.map((role) => (
          <option key={role.name} value={role.name}>
            {role.name}
          </option>
        ))}
      </select>
    </label>
  );
}

export function RoleForm({ user, roles }: { user: User; roles: RoleInfo[] }) {
  const router = useRouter();
  const [status, setStatus] = useState<Status>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const role = String(new FormData(event.currentTarget).get("role"));
    const result = await sendJson(`/api/users/${user.id}/role`, "PUT", { role });
    if (!result.ok) {
      setStatus({ kind: "error", text: result.message });
      return;
    }
    setStatus({ kind: "success", text: "Role updated" });
    router.refresh();
  }

  return (
    <form onSubmit={submit} className="card">
      <h2>Role</h2>
      <RoleSelect roles={roles} value={user.role} />
      <button>Assign role</button>
      <StatusLine status={status} />
    </form>
  );
}

export function DeactivateButton({ userId }: { userId: number }) {
  const router = useRouter();
  const [status, setStatus] = useState<Status>(null);

  async function deactivate() {
    if (!window.confirm("Deactivate this user? They will be signed out immediately.")) return;
    const result = await sendJson(`/api/users/${userId}/deactivate`, "POST");
    if (!result.ok) {
      setStatus({ kind: "error", text: result.message });
      return;
    }
    router.refresh();
  }

  return (
    <div className="card">
      <h2>Account</h2>
      <button className="danger" onClick={deactivate}>
        Deactivate user
      </button>
      <StatusLine status={status} />
    </div>
  );
}

export function CreateUserForm({ roles }: { roles: RoleInfo[] }) {
  const router = useRouter();
  const [status, setStatus] = useState<Status>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const body = Object.fromEntries(new FormData(event.currentTarget));
    const result = await sendJson<User>("/api/users", "POST", body);
    if (!result.ok) {
      setStatus({ kind: "error", text: result.message });
      return;
    }
    router.push(`/users/${result.data.id}`);
  }

  return (
    <form onSubmit={submit} className="card">
      <h2>New user</h2>
      <label>
        Email
        <input name="email" type="email" required />
      </label>
      <label>
        Name
        <input name="name" required />
      </label>
      <label>
        Password
        <input name="password" type="password" required minLength={8} />
      </label>
      <RoleSelect roles={roles} />
      <button>Create user</button>
      <StatusLine status={status} />
    </form>
  );
}

const permissionKey = (p: Permission) => `${p.obj}:${p.act}:${p.scope}`;

export function CreateRoleForm({ grantable }: { grantable: Permission[] }) {
  const router = useRouter();
  const [status, setStatus] = useState<Status>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const selected = new Set(data.getAll("permission").map(String));
    const result = await sendJson("/api/roles", "POST", {
      name: data.get("name"),
      permissions: grantable.filter((p) => selected.has(permissionKey(p))),
    });
    if (!result.ok) {
      setStatus({ kind: "error", text: result.message });
      return;
    }
    router.push("/users");
  }

  return (
    <form onSubmit={submit} className="card">
      <h2>New role</h2>
      <label>
        Name
        <input name="name" required pattern="[a-z][a-z0-9\-]{1,63}" />
      </label>
      <fieldset>
        <legend>Permissions</legend>
        {grantable.map((p) => (
          <label key={permissionKey(p)} className="check">
            <input type="checkbox" name="permission" value={permissionKey(p)} />
            {p.obj} / {p.act} ({p.scope})
          </label>
        ))}
      </fieldset>
      <button>Create role</button>
      <StatusLine status={status} />
    </form>
  );
}
