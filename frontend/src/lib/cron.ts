/**
 * Convert human-readable frequency to cron expression
 * @param frequency - Human frequency string (e.g., "1h", "1 día", "1 semana")
 * @returns Cron expression string
 */
export function humanFrequencyToCron(frequency: string): string {
  const map: Record<string, string> = {
    "1h": "0 * * * *",
    "3h": "0 */3 * * *",
    "6h": "0 */6 * * *",
    "12h": "0 */12 * * *",
    "1 día": "0 0 * * *",
    "1 semana": "0 0 * * 1",
    "1 mes": "0 0 1 * *",
  };
  return map[frequency] || "";
}

/**
 * Convert cron expression to human-readable frequency
 * @param cronExpr - Cron expression string
 * @returns Human frequency string or "Custom" if not recognized
 */
export function cronToHumanFrequency(cronExpr: string): string {
  const reverseMap: Record<string, string> = {
    "0 * * * *": "1h",
    "0 */3 * * *": "3h",
    "0 */6 * * *": "6h",
    "0 */12 * * *": "12h",
    "0 0 * * *": "1 día",
    "0 0 * * 1": "1 semana",
    "0 0 1 * *": "1 mes",
  };
  return reverseMap[cronExpr] || "Custom";
}

/**
 * List of available human frequency options
 */
export const FREQUENCY_OPTIONS = [
  { value: "1h", label: "Every hour" },
  { value: "3h", label: "Every 3 hours" },
  { value: "6h", label: "Every 6 hours" },
  { value: "12h", label: "Every 12 hours" },
  { value: "1 día", label: "Daily" },
  { value: "1 semana", label: "Weekly" },
  { value: "1 mes", label: "Monthly" },
  { value: "Custom", label: "Custom (Cron expression)" },
];
