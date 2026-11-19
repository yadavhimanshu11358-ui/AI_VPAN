import React from "react";
import { BarChart3, TrendingUp, ShieldAlert, Layers } from "lucide-react";

interface SecurityAnalyticsChartsProps {
  vulnerabilities: any[];
  rawHeaders: Record<string, string>;
  sslValid: boolean;
  scanHistory: any[];
}

export const SecurityAnalyticsCharts: React.FC<SecurityAnalyticsChartsProps> = ({
  vulnerabilities = [],
  rawHeaders = {},
  sslValid = false,
  scanHistory = [],
}) => {
  // 1. Severity Counts for Bar Graph
  const counts = {
    critical: vulnerabilities.filter((v) => v.severity === "critical").length,
    high: vulnerabilities.filter((v) => v.severity === "high").length,
    medium: vulnerabilities.filter((v) => v.severity === "medium").length,
    low: vulnerabilities.filter((v) => v.severity === "low").length,
    info: vulnerabilities.filter((v) => v.severity === "info").length,
  };

  const maxCount = Math.max(1, ...Object.values(counts));

  const severityBars = [
    { label: "Critical", count: counts.critical, color: "from-red-600 to-rose-400", text: "text-red-400" },
    { label: "High", count: counts.high, color: "from-orange-600 to-amber-400", text: "text-orange-400" },
    { label: "Medium", count: counts.medium, color: "from-yellow-500 to-amber-300", text: "text-yellow-400" },
    { label: "Low", count: counts.low, color: "from-cyan-600 to-blue-400", text: "text-cyan-400" },
    { label: "Info", count: counts.info, color: "from-slate-600 to-slate-400", text: "text-slate-400" },
  ];

  // 2. Security Pillar Scores (0 - 100%)
  const hasHeader = (name: string) =>
    Object.keys(rawHeaders).some((k) => k.toLowerCase() === name.toLowerCase());

  const tlsScore = (sslValid ? 60 : 0) + (hasHeader("Strict-Transport-Security") ? 40 : 0);
  const xssScore = hasHeader("Content-Security-Policy") ? 100 : 20;
  const browserGuardScore =
    (hasHeader("X-Frame-Options") ? 40 : 0) +
    (hasHeader("X-Content-Type-Options") ? 35 : 0) +
    (hasHeader("Referrer-Policy") ? 25 : 0);
  const hardeningScore =
    (!hasHeader("Server") ? 50 : 15) +
    (hasHeader("Permissions-Policy") ? 50 : 15);

  const pillars = [
    { name: "TLS & Transport Layer", score: tlsScore, color: "bg-emerald-500" },
    { name: "XSS & Script Isolation (CSP)", score: xssScore, color: "bg-cyan-500" },
    { name: "Browser & Frame Protection", score: browserGuardScore, color: "bg-purple-500" },
    { name: "Server Surface Hardening", score: hardeningScore, color: "bg-amber-500" },
  ];

  // 3. Trend Graph Points (reversed so oldest -> newest)
  const orderedHistory = [...scanHistory].reverse();

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
      {/* Graph 1: Severity Distribution Bar Chart */}
      <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800/90 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-4">
          <span className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
            <BarChart3 className="w-4 h-4 text-emerald-400" />
            Severity Distribution
          </span>
          <span className="text-[11px] font-mono text-slate-500">
            Total: {vulnerabilities.length}
          </span>
        </div>

        <div className="flex items-end justify-between gap-3 h-36 pt-4 px-2 border-b border-slate-800/80">
          {severityBars.map((bar) => {
            const heightPct = bar.count === 0 ? 6 : Math.max(18, Math.round((bar.count / maxCount) * 100));
            return (
              <div key={bar.label} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end group">
                <span className={`text-xs font-mono font-bold ${bar.text}`}>
                  {bar.count}
                </span>
                <div className="w-full bg-slate-900/90 rounded-t-md h-24 flex items-end overflow-hidden p-0.5">
                  <div
                    style={{ height: `${heightPct}%` }}
                    className={`w-full rounded-t bg-gradient-to-t ${bar.color} transition-all duration-700 group-hover:brightness-125`}
                  />
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex justify-between gap-3 px-2 pt-2">
          {severityBars.map((bar) => (
            <span key={bar.label} className="flex-1 text-center text-[10px] font-mono text-slate-400">
              {bar.label}
            </span>
          ))}
        </div>
      </div>

      {/* Graph 2: Defense-in-Depth Pillar Breakdown */}
      <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800/90 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-3">
          <span className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
            <Layers className="w-4 h-4 text-cyan-400" />
            Defense-in-Depth Pillars
          </span>
          <span className="text-[11px] font-mono text-cyan-400">Live Telemetry</span>
        </div>

        <div className="space-y-3 my-auto">
          {pillars.map((pillar) => (
            <div key={pillar.name} className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-slate-300">{pillar.name}</span>
                <span className="font-mono font-semibold text-slate-200">{pillar.score}%</span>
              </div>
              <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div
                  style={{ width: `${pillar.score}%` }}
                  className={`h-full ${pillar.color} rounded-full transition-all duration-700`}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Graph 3: Live Audit Score Trend Line Chart */}
      <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800/90 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-3">
          <span className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
            <TrendingUp className="w-4 h-4 text-purple-400" />
            Audit Posture Comparison
          </span>
          <span className="text-[11px] font-mono text-slate-500">
            {orderedHistory.length} Target(s)
          </span>
        </div>

        {orderedHistory.length > 0 ? (
          <div className="flex flex-col justify-between h-full">
            <svg viewBox="0 0 260 110" className="w-full h-32 overflow-visible">
              <defs>
                <linearGradient id="scoreAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10b981" stopOpacity="0.35" />
                  <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {/* Horizontal Reference Grid */}
              {[20, 55, 90].map((yPos) => (
                <line
                  key={yPos}
                  x1="10"
                  y1={yPos}
                  x2="250"
                  y2={yPos}
                  stroke="#1e293b"
                  strokeDasharray="3 3"
                  strokeWidth="1"
                />
              ))}

              {orderedHistory.length > 1 && (() => {
                const points = orderedHistory.map((item, idx) => {
                  const x = 20 + (idx * 220) / (orderedHistory.length - 1);
                  const y = 95 - ((item.securityScore || 0) / 100) * 80;
                  return `${x},${y}`;
                });
                const areaPath = `M 20,95 L ${points.join(" L ")} L 240,95 Z`;
                return (
                  <>
                    <path d={areaPath} fill="url(#scoreAreaGrad)" />
                    <polyline
                      fill="none"
                      stroke="#10b981"
                      strokeWidth="2.5"
                      points={points.join(" ")}
                    />
                  </>
                );
              })()}

              {orderedHistory.map((item, idx) => {
                const x =
                  orderedHistory.length === 1
                    ? 130
                    : 20 + (idx * 220) / (orderedHistory.length - 1);
                const y = 95 - ((item.securityScore || 0) / 100) * 80;
                return (
                  <g key={idx}>
                    <circle
                      cx={x}
                      cy={y}
                      r="4.5"
                      fill="#060b14"
                      stroke="#10b981"
                      strokeWidth="2.5"
                    />
                    <text
                      x={x}
                      y={y - 9}
                      textAnchor="middle"
                      fill="#6ee7b7"
                      fontSize="10"
                      fontFamily="monospace"
                    >
                      {item.securityScore}
                    </text>
                    <text
                      x={x}
                      y="108"
                      textAnchor="middle"
                      fill="#94a3b8"
                      fontSize="8.5"
                      fontFamily="monospace"
                    >
                      {item.scanMetadata.rawTarget.slice(0, 12)}
                    </text>
                  </g>
                );
              })}
            </svg>
            <p className="text-[11px] text-slate-400 text-center mt-1">
              Scan multiple targets to compare security posture trends
            </p>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-32 text-slate-500 text-xs gap-1">
            <ShieldAlert className="w-5 h-5" />
            <span>Awaiting telemetry data</span>
          </div>
        )}
      </div>
    </div>
  );
};