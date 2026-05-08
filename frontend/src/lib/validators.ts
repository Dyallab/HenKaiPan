import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});

export const projectSchema = z.object({
  name: z.string().min(1, "Name is required").max(255, "Name must not exceed 255 characters"),
  description: z.string().max(1000, "Description must not exceed 1000 characters").optional(),
  repoUrl: z.string().url("Invalid URL format").optional().or(z.literal("")),
});

export const findingSchema = z.object({
  status: z.enum(["open", "in_review", "accepted_risk", "fixed", "verified"]),
  notes: z.string().max(5000, "Notes must not exceed 5000 characters").optional(),
});

export const scanSchema = z.object({
  projectId: z.string().uuid("Invalid project ID format"),
  scannerType: z.string().min(1, "Scanner type is required"),
});

export const bulkFindingsSchema = z.object({
  ids: z.array(z.string().uuid("Invalid finding ID format")).min(1, "At least one finding ID is required"),
  status: z.enum(["open", "in_review", "accepted_risk", "fixed", "verified"]),
});

export type LoginInput = z.infer<typeof loginSchema>;
export type ProjectInput = z.infer<typeof projectSchema>;
export type FindingInput = z.infer<typeof findingSchema>;
export type ScanInput = z.infer<typeof scanSchema>;
export type BulkFindingsInput = z.infer<typeof bulkFindingsSchema>;
