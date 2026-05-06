"use client";

import { useEffect, useState } from "react";

const GITHUB_LOGIN_URL = "http://localhost:8000/api/auth/github/login";

function FeaturePill({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-full border border-cyan-400/25 bg-cyan-500/10 px-4 py-2 text-xs text-cyan-200 backdrop-blur-sm sm:text-sm animate-fade-in">
      <span className="mr-2 text-cyan-100/70">{label}</span>
      <span className="font-semibold tracking-wide text-cyan-100">{value}</span>
    </div>
  );
}

function CapabilityCard({
  title,
  description,
  icon,
  delay,
}: {
  title: string;
  description: string;
  icon: React.ReactNode;
  delay: number;
}) {
  return (
    <div
      className="group rounded-2xl border border-slate-700/50 bg-slate-900/40 p-6 backdrop-blur-sm shadow-lg transition duration-500 hover:border-cyan-400/40 hover:bg-slate-900/60 hover:shadow-[0_0_20px_rgba(6,182,212,0.2)]"
      style={{
        animation: `slideUp 0.6s ease-out ${delay}s both`,
      }}
    >
      <div className="mb-3 inline-block rounded-lg bg-cyan-500/10 p-3 text-cyan-400 transition group-hover:bg-cyan-500/20 group-hover:text-cyan-300">
        {icon}
      </div>
      <p className="text-xs uppercase tracking-[0.22em] text-slate-400">{title}</p>
      <p className="mt-3 text-sm leading-relaxed text-slate-300">{description}</p>
    </div>
  );
}

export default function HomePage() {
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    setIsLoaded(true);
  }, []);

  return (
    <main className="relative min-h-screen overflow-hidden bg-slate-950 text-slate-100">
      <style>{`
        @keyframes slideUp {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        @keyframes fadeIn {
          from {
            opacity: 0;
          }
          to {
            opacity: 1;
          }
        }
        @keyframes glow {
          0%, 100% {
            box-shadow: 0 0 20px rgba(6, 182, 212, 0.3);
          }
          50% {
            box-shadow: 0 0 30px rgba(6, 182, 212, 0.5);
          }
        }
        @keyframes float {
          0%, 100% {
            transform: translateY(0px);
          }
          50% {
            transform: translateY(-10px);
          }
        }
        .animate-fade-in {
          animation: fadeIn 0.8s ease-out;
        }
        .animate-glow {
          animation: glow 3s ease-in-out infinite;
        }
        .animate-float {
          animation: float 6s ease-in-out infinite;
        }
      `}</style>

      {/* Animated gradient background */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_15%_20%,rgba(6,182,212,0.25),transparent_42%),radial-gradient(circle_at_80%_0%,rgba(16,185,129,0.2),transparent_38%),linear-gradient(130deg,rgba(2,6,23,1)_0%,rgba(3,7,18,1)_42%,rgba(2,6,23,1)_100%)]" />
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(148,163,184,0.06)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.06)_1px,transparent_1px)] bg-[size:42px_42px] opacity-20" />

      {/* Floating accent elements */}
      <div className="pointer-events-none absolute top-20 left-[10%] h-72 w-72 rounded-full bg-cyan-500/5 blur-3xl animate-float" />
      <div className="pointer-events-none absolute bottom-40 right-[5%] h-96 w-96 rounded-full bg-emerald-500/5 blur-3xl animate-float" style={{ animationDelay: "2s" }} />

      <section className="relative mx-auto flex min-h-screen w-full max-w-7xl flex-col justify-center px-6 py-20 sm:px-10">
        <div className="space-y-12">
          {/* Badge */}
          <div
            className="inline-flex items-center gap-2 rounded-full border border-emerald-400/40 bg-emerald-500/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-[0.24em] text-emerald-200 backdrop-blur-sm"
            style={{
              animation: isLoaded ? "slideUp 0.6s ease-out 0.1s both" : "none",
            }}
          >
            SentinelFlow
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-300 animate-pulse" />
            Dependency Security Analysis
          </div>

          {/* Main heading */}
          <div className="max-w-5xl space-y-8">
            <div
              style={{
                animation: isLoaded ? "slideUp 0.6s ease-out 0.2s both" : "none",
              }}
            >
              <h1 className="font-['Rajdhani',_Space_Grotesk,_sans-serif] text-5xl font-bold leading-[1.1] tracking-tight text-slate-100 sm:text-6xl lg:text-7xl">
                Protect Your
                <br />
                <span className="inline-block bg-gradient-to-r from-cyan-300 via-emerald-300 to-cyan-300 bg-clip-text text-transparent">
                  Repository Dependencies
                </span>
              </h1>
            </div>

            <div
              className="max-w-2xl space-y-4"
              style={{
                animation: isLoaded ? "slideUp 0.6s ease-out 0.3s both" : "none",
              }}
            >
              <p className="text-base leading-relaxed text-slate-300 sm:text-lg">
                SentinelFlow scans your GitHub repositories to identify security risks, vulnerabilities, and suspicious dependencies in your project's dependency tree. Get comprehensive analysis across npm and PyPI ecosystems in one unified dashboard.
              </p>
              <p className="text-base leading-relaxed text-slate-400 sm:text-lg">
                Detect malware, perform static and dynamic analysis, and make informed decisions about which packages are safe for production.
              </p>
            </div>
          </div>

          {/* Feature pills */}
          <div
            className="flex flex-wrap gap-3"
            style={{
              animation: isLoaded ? "slideUp 0.6s ease-out 0.4s both" : "none",
            }}
          >
            <FeaturePill label="Multi-ecosystem" value="npm & PyPI" />
            <FeaturePill label="Security scanning" value="Full analysis" />
            <FeaturePill label="Repository access" value="GitHub integrated" />
          </div>

          {/* CTA Button */}
          <div
            className="flex flex-col gap-4 sm:flex-row sm:items-center"
            style={{
              animation: isLoaded ? "slideUp 0.6s ease-out 0.5s both" : "none",
            }}
          >
            <a
              href={GITHUB_LOGIN_URL}
              className="group inline-flex items-center justify-center gap-3 rounded-xl border border-cyan-300/50 bg-gradient-to-r from-cyan-400/20 to-cyan-500/20 px-8 py-4 text-sm font-semibold tracking-wide text-cyan-100 shadow-[0_14px_28px_-12px_rgba(6,182,212,0.65)] transition duration-300 hover:border-cyan-200/80 hover:from-cyan-400/30 hover:to-cyan-500/30 hover:text-white hover:shadow-[0_20px_40px_-12px_rgba(6,182,212,0.8)]"
            >
              <span>Connect Your Repository</span>
              <span aria-hidden="true" className="transition group-hover:translate-x-1">→</span>
            </a>
            <p className="text-sm text-slate-400">
              Sign in with GitHub to get started
            </p>
          </div>
        </div>

        {/* Capability cards grid */}
        <div className="mt-24 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          <CapabilityCard
            title="Repository scanning"
            description="Connect your GitHub account and select repositories to scan their complete dependency trees across npm and PyPI ecosystems."
            icon={
              <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4m0 0L4 7m16 0l-8 4m0 0l8 4m-8-4v10l8-4m-16-4l8-4m0 0l8 4m0 0v10l-8-4" />
              </svg>
            }
            delay={0.6}
          />
          <CapabilityCard
            title="Vulnerability detection"
            description="Run static and dynamic analysis to identify malware, known vulnerabilities, and suspicious package behavior in your dependencies."
            icon={
              <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            }
            delay={0.7}
          />
          <CapabilityCard
            title="Dependency insights"
            description="Browse package metadata, view security status, generate software bills of materials, and understand your project's supply chain."
            icon={
              <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            }
            delay={0.8}
          />
        </div>

        {/* Bottom accent line */}
        <div className="mt-24 flex justify-center">
          <div className="h-px w-32 bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent" />
        </div>
      </section>
    </main>
  );
}
