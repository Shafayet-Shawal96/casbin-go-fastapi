export type Permission = { obj: string; act: string; scope: "any" | "own" };

export type User = {
  id: number;
  email: string;
  name: string;
  phone: string | null;
  role: string;
  is_active: boolean;
  company_name: string | null;
  department: string | null;
  designation: string | null;
};

export type CurrentUser = User & { permissions: Permission[] };

export type RoleInfo = { name: string; is_builtin: boolean; assignable: boolean };

export type RolesResponse = { roles: RoleInfo[]; grantable: Permission[] };

export type UserList = { items: User[]; total: number; limit: number; offset: number };
