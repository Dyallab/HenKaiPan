import { api, type User } from "./api";
import { toast } from "./toast";

let _cachedUser: User | null = null;

/**
 * Capability matrix per role. Add new roles here — UI and API checks derive from this.
 */
const ROLE_CAPABILITIES: Record<string, { read: boolean; write: boolean }> = {
    admin:  { read: true, write: true },
    viewer: { read: true, write: false },
};

/**
 * Get the current authenticated user.
 * Results are cached for the session lifetime.
 */
export async function getCurrentUser(): Promise<User | null> {
    if (_cachedUser) return _cachedUser;
    try {
        _cachedUser = await api.getMe();
        return _cachedUser;
    } catch {
        return null;
    }
}

function has(capability: "read" | "write"): boolean {
    return ROLE_CAPABILITIES[_cachedUser?.role ?? ""]?.[capability] ?? false;
}

export function canRead(): boolean {
    return has("read");
}

export function canWrite(): boolean {
    return has("write");
}

/**
 * Require the current user to have one of the allowed roles.
 * Redirects to /dashboard with an error toast if unauthorized.
 * Redirects to /login if not authenticated.
 *
 * Usage in any page script:
 *   import { requireRole } from "@lib/auth";
 *   await requireRole(["admin"]);
 */
export async function requireRole(allowed: string[]): Promise<User> {
    const user = await getCurrentUser();
    if (!user) {
        window.location.href = "/login";
        throw new Error("unauthorized");
    }
    if (!allowed.includes(user.role)) {
        toast("Access denied. Admin only.", "error");
        window.location.href = "/dashboard";
        throw new Error("forbidden");
    }
    return user;
}
