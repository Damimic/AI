import { Bot, MessageCircle, RotateCcw, ShieldCheck, X } from "lucide-react";
import { useState } from "react";
import type { Finding } from "../lib/api";
import { CHAT_NODES, ROOT_QUESTIONS, type ChatContext } from "../lib/auditChat";

interface Message {
  role: "user" | "assistant";
  text: string;
}

interface ChatWidgetProps {
  findings: Finding[];
  hostnames: string[];
}

export function ChatWidget({ findings, hostnames }: ChatWidgetProps) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [options, setOptions] = useState<string[]>(ROOT_QUESTIONS);

  const ctx: ChatContext = { findings, hostnames };

  function pick(nodeId: string) {
    const node = CHAT_NODES[nodeId];
    if (!node) return;
    setMessages((prev) => [
      ...prev,
      { role: "user", text: node.question },
      { role: "assistant", text: node.answer(ctx) },
    ]);
    setOptions(node.followUps);
  }

  function reset() {
    setMessages([]);
    setOptions(ROOT_QUESTIONS);
  }

  return (
    <>
      <button
        onClick={() => setOpen((o) => !o)}
        className="fixed bottom-6 right-6 z-50 flex size-14 items-center justify-center rounded-full bg-brand-600 text-white shadow-lg transition-transform hover:scale-105 hover:bg-brand-700"
        aria-label={open ? "Close assistant" : "Open assistant"}
      >
        {open ? <X className="size-6" /> : <MessageCircle className="size-6" />}
      </button>

      {open && (
        <div className="fixed bottom-24 right-6 z-50 flex h-[32rem] w-96 max-w-[calc(100vw-3rem)] flex-col overflow-hidden rounded-2xl bg-white shadow-2xl ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-700">
          <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
            <div className="flex items-center gap-2">
              <div className="flex size-7 items-center justify-center rounded-lg bg-brand-600 text-white">
                <ShieldCheck className="size-4" />
              </div>
              <div>
                <div className="text-sm font-semibold text-slate-900 dark:text-white">Kepler Assistant</div>
                <div className="text-xs text-amber-600 dark:text-amber-400">Simulated preview — not live AI</div>
              </div>
            </div>
            {messages.length > 0 && (
              <button
                onClick={reset}
                className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
                aria-label="Start over"
              >
                <RotateCcw className="size-3.5" />
                Start over
              </button>
            )}
          </div>

          <div className="flex-1 space-y-3 overflow-y-auto px-4 py-4">
            {messages.length === 0 && (
              <div className="flex gap-2">
                <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800">
                  <Bot className="size-4 text-slate-500 dark:text-slate-400" />
                </div>
                <div className="rounded-2xl rounded-tl-sm bg-slate-100 px-3 py-2 text-sm text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  Hi — pick a question below and I'll walk through what your current findings show, auditor-style.
                </div>
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`flex gap-2 ${m.role === "user" ? "justify-end" : ""}`}>
                {m.role === "assistant" && (
                  <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800">
                    <Bot className="size-4 text-slate-500 dark:text-slate-400" />
                  </div>
                )}
                <div
                  className={
                    m.role === "user"
                      ? "max-w-[80%] rounded-2xl rounded-tr-sm bg-brand-600 px-3 py-2 text-sm text-white"
                      : "max-w-[80%] rounded-2xl rounded-tl-sm bg-slate-100 px-3 py-2 text-sm text-slate-700 dark:bg-slate-800 dark:text-slate-300"
                  }
                >
                  {m.text}
                </div>
              </div>
            ))}
          </div>

          <div className="border-t border-slate-200 p-3 dark:border-slate-800">
            <div className="mb-1.5 text-xs font-medium text-slate-400 dark:text-slate-500">
              {messages.length === 0 ? "Try asking:" : "Follow up:"}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {options.map((id) => (
                <button
                  key={id}
                  onClick={() => pick(id)}
                  className="rounded-full border border-brand-200 bg-brand-50 px-3 py-1.5 text-left text-xs font-medium text-brand-700 transition-colors hover:bg-brand-100 dark:border-brand-500/30 dark:bg-brand-500/10 dark:text-brand-300 dark:hover:bg-brand-500/20"
                >
                  {CHAT_NODES[id]?.question}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
