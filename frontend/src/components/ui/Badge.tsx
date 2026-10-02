import clsx from "clsx";

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-950/50 dark:text-red-400 dark:ring-red-400/30",
  HIGH: "bg-orange-50 text-orange-700 ring-orange-600/20 dark:bg-orange-950/50 dark:text-orange-400 dark:ring-orange-400/30",
  MEDIUM: "bg-amber-50 text-amber-700 ring-amber-600/20 dark:bg-amber-950/50 dark:text-amber-400 dark:ring-amber-400/30",
  LOW: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-400 dark:ring-slate-400/20",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.LOW;
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset",
        style,
      )}
    >
      {severity}
    </span>
  );
}

const STATUS_META: Record<string, { label: string; dot: string; text: string }> = {
  fixed: { label: "Fixed", dot: "bg-emerald-500", text: "text-emerald-700 dark:text-emerald-400" },
  will_not_fix: { label: "Will not fix", dot: "bg-red-500", text: "text-red-700 dark:text-red-400" },
  end_of_life: { label: "End of life", dot: "bg-red-500", text: "text-red-700 dark:text-red-400" },
  affected: { label: "Affected", dot: "bg-amber-500", text: "text-amber-700 dark:text-amber-400" },
  under_investigation: { label: "Under investigation", dot: "bg-amber-500", text: "text-amber-700 dark:text-amber-400" },
  fix_deferred: { label: "Fix deferred", dot: "bg-amber-500", text: "text-amber-700 dark:text-amber-400" },
  not_affected: { label: "Not affected", dot: "bg-slate-400", text: "text-slate-600 dark:text-slate-400" },
};

export function StatusBadge({ status }: { status?: string }) {
  if (!status) {
    return <span className="text-sm text-slate-400 dark:text-slate-500">—</span>;
  }
  const meta = STATUS_META[status] ?? {
    label: status,
    dot: "bg-slate-400",
    text: "text-slate-600 dark:text-slate-400",
  };
  return (
    <span className={clsx("inline-flex items-center gap-1.5 text-sm font-medium", meta.text)}>
      <span className={clsx("size-1.5 rounded-full", meta.dot)} />
      {meta.label}
    </span>
  );
}
