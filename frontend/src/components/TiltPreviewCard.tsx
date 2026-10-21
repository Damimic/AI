import { type MouseEvent, type ReactNode, useRef, useState } from "react";

interface TiltPreviewCardProps {
  children: ReactNode;
}

/**
 * A card that tilts toward the cursor in 3D, in the spirit of Cult UI's
 * "interactions rather than surfaces" philosophy — something that
 * responds, not just a static screenshot. Built from scratch with plain
 * mouse events and a CSS transform (no animation library): the technique
 * itself (perspective + rotateX/rotateY driven by pointer offset from
 * center) is a generic, long-established one, not any single library's
 * proprietary implementation.
 */
export function TiltPreviewCard({ children }: TiltPreviewCardProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [transform, setTransform] = useState("perspective(1000px) rotateX(0deg) rotateY(0deg)");
  const [glow, setGlow] = useState({ x: 50, y: 50, opacity: 0 });

  function handleMouseMove(e: MouseEvent<HTMLDivElement>) {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;

    // Small angles only — this is a dashboard preview, not a gimmick.
    const rotateY = ((x - centerX) / centerX) * 6;
    const rotateX = -((y - centerY) / centerY) * 6;

    setTransform(`perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`);
    setGlow({ x: (x / rect.width) * 100, y: (y / rect.height) * 100, opacity: 1 });
  }

  function handleMouseLeave() {
    setTransform("perspective(1000px) rotateX(0deg) rotateY(0deg)");
    setGlow((g) => ({ ...g, opacity: 0 }));
  }

  return (
    <div
      ref={ref}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={{ transform, transition: "transform 150ms ease-out" }}
      className="relative overflow-hidden rounded-2xl bg-white shadow-2xl ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800"
    >
      {/* Cursor-following highlight — the part that actually sells "this responds to you," not just "this has a shadow." */}
      <div
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300"
        style={{
          opacity: glow.opacity * 0.15,
          background: `radial-gradient(400px circle at ${glow.x}% ${glow.y}%, var(--color-brand-400), transparent 70%)`,
        }}
      />
      <div className="relative">{children}</div>
    </div>
  );
}
