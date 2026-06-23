/**
 * lib/schemas.ts
 * Zod v4 schemas for all form inputs and API responses.
 * These mirror the backend Pydantic models in schemas.py.
 */
import { z } from 'zod';

// ── Auth ──────────────────────────────────────────────────────────────────────

export const LoginSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
});

export const RegisterSchema = z
  .object({
    username: z
      .string()
      .min(3, 'Username must be at least 3 characters')
      .max(50, 'Username must be 50 characters or less')
      .regex(/^\w+$/, 'Username may only contain letters, numbers, and underscores'),
    email: z.string().min(1, 'Email is required').email('Invalid email address'),
    password: z.string().min(6, 'Password must be at least 6 characters'),
    confirmPassword: z.string().min(1, 'Please confirm your password'),
  })
  .refine(data => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  });

// ── Admin — alert settings ────────────────────────────────────────────────────

export const AlertSettingsSchema = z
  .object({
    max_attempts_to_block: z
      .number()
      .int('Must be a whole number')
      .min(1, 'Minimum 1')
      .max(100, 'Maximum 100'),
    warning_window_minutes: z
      .number()
      .int('Must be a whole number')
      .min(1, 'Minimum 1 minute')
      .max(1440, 'Maximum 1440 minutes (24 h)'),
    block_duration_minutes: z
      .number()
      .int('Must be a whole number')
      .min(1, 'Minimum 1 minute')
      .max(10080, 'Maximum 10080 minutes (7 days)'),
    max_temp_blocks: z
      .number()
      .int('Must be a whole number')
      .min(1, 'Minimum 1')
      .max(20, 'Maximum 20'),
    enable_email: z.boolean(),
    enable_telegram: z.boolean(),
    email_address: z.string(),
    telegram_chat_id: z.string(),
  })
  .superRefine((data, ctx) => {
    if (data.enable_email && !data.email_address) {
      ctx.addIssue({
        code: 'custom',
        message: 'Email address is required when email alerts are enabled',
        path: ['email_address'],
      });
    } else if (data.enable_email && data.email_address) {
      const emailResult = z.string().email().safeParse(data.email_address);
      if (!emailResult.success) {
        ctx.addIssue({
          code: 'custom',
          message: 'Invalid email address',
          path: ['email_address'],
        });
      }
    }
    if (data.enable_telegram && !data.telegram_chat_id) {
      ctx.addIssue({
        code: 'custom',
        message: 'Telegram chat ID is required when Telegram alerts are enabled',
        path: ['telegram_chat_id'],
      });
    }
  });

// ── API response schemas ──────────────────────────────────────────────────────

export const UserSchema = z.object({
  id: z.number(),
  username: z.string(),
  email: z.string(),
  role: z.enum(['admin', 'user']),
  is_blocked: z.boolean().optional(),
  failed_attempts: z.number().optional(),
  temp_blocks: z.number().optional(),
});

export const AuthResponseSchema = z.object({
  token: z.string().min(1),
  user: UserSchema,
});

export const FeatureFlagsSchema = z.object({
  INPUT_UNICODE_FIREWALL: z.boolean(),
  INPUT_SPACY_FIREWALL: z.boolean(),
  BERT_FIREWALL: z.boolean(),
  INPUT_PII_FIREWALL: z.boolean(),
  INPUT_CONTEXT_RELEVANCE: z.boolean(),
  OUTPUT_SPACY_FIREWALL: z.boolean(),
  OUTPUT_PII_FIREWALL: z.boolean(),
  OUTPUT_CONTEXT_RELEVANCE: z.boolean(),
  DOCUMENT_PROCESSING: z.boolean(),
  bert_settings: z.object({
    SAFE_THRESHOLD: z.number(),
    MEDIUM_THRESHOLD: z.number(),
    MAX_REPHRASE: z.number(),
    ACTIVE_MODEL: z.string(),
  }),
});

export const SecurityLogSchema = z.object({
  id: z.number(),
  timestamp: z.string(),
  user_id: z.number().nullable(),
  username: z.string().nullable(),
  prompt: z.string(),
  detection_type: z.string(),
  action: z.string(),
  severity: z.string(),
  details: z.record(z.string(), z.unknown()).nullable(),
});

// ── Utility ───────────────────────────────────────────────────────────────────

/** Extract a flat field-error map from a ZodError for easy per-field rendering. */
export function flattenZodErrors(error: z.ZodError): Record<string, string> {
  const out: Record<string, string> = {};
  for (const issue of error.issues) {
    const key = issue.path.join('.') || '_root';
    if (!out[key]) out[key] = issue.message;
  }
  return out;
}

export type LoginInput    = z.infer<typeof LoginSchema>;
export type RegisterInput = z.infer<typeof RegisterSchema>;
export type AlertInput    = z.infer<typeof AlertSettingsSchema>;
