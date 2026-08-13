import { OWNMESH_WORDMARK_SVG_BASE64 } from "./brand-wordmark.ts";

export const AUTH_PAGE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/**
 * Consent POSTs return through the client's already-validated redirect URI.
 * Chrome applies form-action to that redirect as well, so admit only its
 * canonical origin while keeping every other form destination blocked.
 */
export function oauthConsentCsp(redirectUri: string): string {
  try {
    const redirect = new URL(redirectUri);
    if (redirect.protocol !== "https:" && redirect.protocol !== "http:") {
      return AUTH_PAGE_CSP;
    }
    return AUTH_PAGE_CSP.replace(
      "form-action 'self'",
      `form-action 'self' ${redirect.origin}`,
    );
  } catch {
    return AUTH_PAGE_CSP;
  }
}

type AuthPageOptions = {
  title: string;
  eyebrow: string;
  heading: string;
  intro: string;
  body: string;
  footer?: string;
  locale?: AuthLocale;
};

export type AuthLocale = "en-US" | "ja-JP" | "zh-Hans" | "ru-RU";

export type AuthText = {
  en: string;
  ja: string;
  zh: string;
  ru: string;
};

function localeFromTag(raw: string): AuthLocale | null {
  const tag = raw.trim().toLowerCase().replace(/_/g, "-");
  if (tag === "ja" || tag.startsWith("ja-")) return "ja-JP";
  if (tag === "zh" || tag.startsWith("zh-")) return "zh-Hans";
  if (tag === "ru" || tag.startsWith("ru-")) return "ru-RU";
  if (tag === "en" || tag.startsWith("en-")) return "en-US";
  return null;
}

/** Resolve one of OwnMesh's four UI locales without reflecting input. */
export function authLocale(request: Request): AuthLocale {
  const url = new URL(request.url);
  for (const raw of [url.searchParams.get("ui_locales"), url.searchParams.get("lang")]) {
    if (!raw) continue;
    for (const candidate of raw.split(/[\s,]+/)) {
      const locale = localeFromTag(candidate);
      if (locale) return locale;
    }
  }
  for (const item of (request.headers.get("accept-language") || "").split(",")) {
    const locale = localeFromTag(item.split(";", 1)[0] || "");
    if (locale) return locale;
  }
  return "en-US";
}

export function authText(locale: AuthLocale, text: AuthText): string {
  switch (locale) {
    case "ja-JP": return text.ja;
    case "zh-Hans": return text.zh;
    case "ru-RU": return text.ru;
    default: return text.en;
  }
}

function escapeText(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Shared, dependency-free browser shell for login and OAuth consent. */
export function authPage(options: AuthPageOptions): string {
  const locale = options.locale || "en-US";
  const status = authText(locale, {
    en: "self-hosted authority / encrypted channel",
    ja: "セルフホスト認証局 / 暗号化チャネル",
    zh: "自托管授权中心 / 加密通道",
    ru: "собственный центр доверия / шифрованный канал",
  });
  const policy = authText(locale, {
    en: "OWNMESH // LOCAL POLICY IS FINAL",
    ja: "OWNMESH // ローカルポリシーが最終権限",
    zh: "OWNMESH // 本地策略拥有最终权限",
    ru: "OWNMESH // ЛОКАЛЬНАЯ ПОЛИТИКА ГЛАВНАЯ",
  });
  const defaultFooter = authText(locale, {
    en: "No central telemetry",
    ja: "中央テレメトリなし",
    zh: "无集中遥测",
    ru: "Без централизованной телеметрии",
  });
  return `<!doctype html><html lang="${locale}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeText(options.title)}</title>
<style>
/* --dim carries 11-14px labels (.eyebrow, .meta dt, .scope small, .foot,
   .version). At #626a75 it measured 3.43:1 on --panel, below the WCAG AA 4.5:1
   floor for normal text; #7d8590 clears it at 4.63:1. */
:root{color-scheme:dark;--bg:#090a0c;--panel:#101216;--panel-2:#0c0e11;--line:#2a2e34;--line-strong:#3a4048;--text:#e5e7ea;--muted:#9299a3;--dim:#7d8590;--ok:#a8b3a3;--danger:#c9a0a0}
*{box-sizing:border-box}html{min-height:100%;background:var(--bg)}body{min-height:100vh;margin:0;color:var(--text);background:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px),radial-gradient(circle at 50% -20%,#20242a 0,transparent 45%);background-size:32px 32px,32px 32px,100% 100%;font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace}
.shell{width:min(100% - 32px,560px);margin:0 auto;padding:7vh 0 40px}.brand{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin:0 2px 22px}.wordmark{display:block;width:min(296px,58vw);height:auto;image-rendering:pixelated}.version{padding-bottom:4px;color:var(--dim);font-size:11px;letter-spacing:.08em;white-space:nowrap}
.status-line{display:flex;align-items:center;gap:9px;margin:0 2px 10px;color:var(--muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}.status-dot{width:7px;height:7px;border:1px solid var(--ok);background:#53604f;box-shadow:0 0 0 3px rgba(168,179,163,.06)}
.panel{border:1px solid var(--line);background:rgba(16,18,22,.96);box-shadow:0 18px 60px rgba(0,0,0,.36)}.panel-head{padding:24px 26px 20px;border-bottom:1px solid var(--line)}.eyebrow{margin:0 0 9px;color:var(--dim);font-size:11px;letter-spacing:.13em;text-transform:uppercase}.panel h1{margin:0;font-size:21px;line-height:1.25;letter-spacing:-.02em}.intro{margin:10px 0 0;color:var(--muted)}.panel-body{padding:24px 26px 26px}
.stack{display:grid;gap:14px}.meta{display:grid;grid-template-columns:110px 1fr;gap:8px 16px;margin:0 0 20px;padding:13px 15px;border:1px solid var(--line);background:var(--panel-2)}.meta dt{color:var(--dim)}.meta dd{min-width:0;margin:0;color:#c7cbd0;overflow-wrap:anywhere}.scope-list{display:grid;gap:8px;margin:0 0 22px}.scope{display:grid;grid-template-columns:9px 1fr;gap:11px;padding:11px 12px;border:1px solid #24282e;background:#0c0e11}.scope-mark{width:7px;height:7px;margin-top:6px;border:1px solid #7e878f;background:#3f454b}.scope strong{display:block;color:#d7dade;font-size:12px;font-weight:600}.scope small{display:block;margin-top:2px;color:var(--dim);line-height:1.45}.note{margin:0 0 20px;padding:12px 14px;border-left:2px solid #5f6871;background:#0c0e11;color:var(--muted);font-size:12px}
label{display:block;margin:0 0 7px;color:#b8bdc4;font-size:12px}input{width:100%;padding:11px 12px;border:1px solid var(--line-strong);border-radius:0;outline:0;background:#090b0e;color:var(--text);font:inherit}input:focus{border-color:#7d858e;box-shadow:0 0 0 2px rgba(125,133,142,.12)}.actions{display:grid;grid-template-columns:1fr auto;gap:10px;margin-top:4px}button{min-height:42px;padding:10px 16px;border:1px solid var(--line-strong);border-radius:0;background:#16191e;color:#cdd1d6;font:600 13px/1 ui-monospace,SFMono-Regular,Menlo,monospace;cursor:pointer}button:hover{border-color:#777f88;background:#1b1f24}button.primary{border-color:#d7dade;background:#d7dade;color:#0c0e11}button.primary:hover{background:#f0f1f2}button.danger{color:#b9a1a1}button:disabled{cursor:wait;opacity:.55}.wide{width:100%}
.status{min-height:22px;margin:12px 0 0;color:var(--danger);font-size:12px}.foot{display:flex;justify-content:space-between;gap:16px;margin:14px 2px 0;color:var(--dim);font-size:11px}.foot span:last-child{text-align:right}code{color:#d9dde1;font:inherit;overflow-wrap:anywhere}pre{max-height:260px;margin:0 0 20px;padding:13px 15px;overflow:auto;border:1px solid var(--line);background:var(--panel-2);color:#c7cbd0;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;overflow-wrap:anywhere}a{color:#c9ced4;text-underline-offset:3px}a:hover{color:#fff}.help{margin-top:14px;border-top:1px solid var(--line);padding-top:12px;color:var(--muted);font-size:12px}.help summary{cursor:pointer;color:#c7cbd0}.help p{margin:10px 0 0}
@media(max-width:560px){.shell{width:min(100% - 20px,560px);padding:24px 0}.brand{align-items:center;margin-bottom:16px}.version{display:none}.panel-head,.panel-body{padding:20px}.meta{grid-template-columns:1fr;gap:2px}.meta dd{margin-bottom:8px}.actions{grid-template-columns:1fr}.actions button{width:100%}.foot{display:block}.foot span{display:block!important;text-align:left!important;margin-top:4px}}
@media(prefers-reduced-motion:no-preference){button,input{transition:border-color .12s ease,background .12s ease,box-shadow .12s ease}}
</style></head><body><main class="shell">
<header class="brand"><img class="wordmark" src="data:image/svg+xml;base64,${OWNMESH_WORDMARK_SVG_BASE64}" alt="OwnMesh"><span class="version">CONTROL / 1.2</span></header>
<div class="status-line"><span class="status-dot" aria-hidden="true"></span><span>${escapeText(status)}</span></div>
<section class="panel"><header class="panel-head"><p class="eyebrow">${escapeText(options.eyebrow)}</p><h1>${escapeText(options.heading)}</h1><p class="intro">${escapeText(options.intro)}</p></header><div class="panel-body">${options.body}</div></section>
<footer class="foot"><span>${escapeText(policy)}</span><span>${escapeText(options.footer || defaultFooter)}</span></footer>
</main></body></html>`;
}
