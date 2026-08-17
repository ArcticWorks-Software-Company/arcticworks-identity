import { redirect } from "@sveltejs/kit";
import type { Actions } from "./$types";

export const actions = {
  default: async ({ cookies }) => {
    cookies.delete("mock_session", { path: "/" });
    throw redirect(303, "/");
  },
} satisfies Actions;
