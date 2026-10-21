/**
 * A soft, slowly-shifting gradient backdrop — the generic "aurora
 * background" technique (a handful of large, blurred, animated gradient
 * blobs behind the content) rather than any single library's specific
 * implementation. Pure CSS, no animation library, no dependency added.
 * Kept subtle and behind the waitlist form: for a security product this
 * is texture, not a focal point.
 */
export function AuroraBackground() {
  return (
    <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[32rem] overflow-hidden">
      <div className="absolute left-1/2 top-0 size-[36rem] rounded-full bg-brand-400/20 blur-3xl animate-aurora-a dark:bg-brand-500/10" />
      <div className="absolute left-1/2 top-0 size-[30rem] rounded-full bg-emerald-300/15 blur-3xl animate-aurora-b dark:bg-emerald-500/10" />
      <div className="absolute left-1/2 top-10 size-[24rem] rounded-full bg-brand-300/15 blur-3xl animate-aurora-c dark:bg-brand-400/10" />
    </div>
  );
}
