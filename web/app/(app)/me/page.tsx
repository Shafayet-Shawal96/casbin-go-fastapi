import { CompanyForm, InfoForm } from "@/components/forms";
import { UserDetails } from "@/components/UserDetails";
import { can, requireUser } from "@/lib/auth";

export default async function MePage() {
  const user = await requireUser();
  return (
    <>
      <h1>My profile</h1>
      <UserDetails user={user} />
      {can(user, "user_info", "update", user.id) && <InfoForm user={user} />}
      {can(user, "company_info", "update", user.id) && <CompanyForm user={user} />}
    </>
  );
}
