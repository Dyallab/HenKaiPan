import { api } from "./api";

let _status: Promise<ConfigStatus> | null = null;

interface ConfigStatus {
    ai: { remediation: boolean; summary: boolean; validation: boolean };
    features: { risk_acceptance: boolean };
    email_enabled: boolean;
    frontend_url: boolean;
    webhook_secret: boolean;
}

export async function getConfigStatus(): Promise<ConfigStatus> {
    if (!_status) {
        _status = api.getConfigStatus().catch(() => ({
            ai: { remediation: false, summary: false, validation: false },
            features: { risk_acceptance: false },
            email_enabled: false,
            frontend_url: false,
            webhook_secret: false,
        }));
    }
    return _status;
}

export function applyConfigGuards(root: ParentNode = document) {
    getConfigStatus().then(cfg => {
        root.querySelectorAll("[data-requires-config]").forEach(el => {
            const path = (el as HTMLElement).dataset.requiresConfig!;
            if (!resolvePath(cfg, path)) {
                el.setAttribute("disabled", "");
                el.setAttribute("title", "Not configured");
            }
        });
    });
}

function resolvePath(obj: any, path: string): boolean {
    return path.split(".").reduce((o, k) => o?.[k], obj) === true;
}
