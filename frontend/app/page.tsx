'use client'

import { useState } from 'react'
import type { ReactNode } from 'react'

const API = process.env.NEXT_PUBLIC_API_BASE || 'https://trustscan-api-q2s4.onrender.com'

type Scan = { scan_id: string; status: string }

type ScanType = [string, string, string, string]

const types: ScanType[] = [
  ['Android APK', 'Static analysis', 'available', 'android'],
  ['URL', 'Web threat analysis', 'soon', 'url'],
  ['Windows EXE', 'File analysis', 'soon', 'windows'],
  ['PDF', 'Document analysis', 'soon', 'document'],
  ['Office files', 'Document analysis', 'soon', 'office'],
  ['Archives', 'Archive analysis', 'soon', 'archive'],
]

async function fetchWithTimeout(url: string, init?: RequestInit, ms = 120000) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), ms)
  try {
    return await fetch(url, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}

export default function Home() {
  const [file, setFile] = useState<File | null>(null)
  const [scan, setScan] = useState<Scan | null>(null)
  const [report, setReport] = useState<any>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function analyze() {
    if (!file) return
    setError('')
    setBusy(true)
    setReport(null)
    setScan(null)

    try {
      const fd = new FormData()
      fd.append('file', file)
      const response = await fetchWithTimeout(`${API}/api/v1/scans`, {
        method: 'POST',
        body: fd,
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw Error(data.detail || `Upload failed (${response.status})`)

      setScan(data)
      let status = data.status

      while (!['COMPLETED', 'FAILED', 'CANCELLED'].includes(status)) {
        await new Promise((resolve) => setTimeout(resolve, 1000))
        const statusResponse = await fetchWithTimeout(
          `${API}/api/v1/scans/${data.scan_id}`,
          undefined,
          30000,
        )
        const statusData = await statusResponse.json()
        if (!statusResponse.ok) throw Error(statusData.detail || 'Could not read scan status')
        status = statusData.status
        setScan(statusData)
      }

      if (status === 'FAILED') throw Error('We could not analyze this APK.')

      const reportResponse = await fetchWithTimeout(
        `${API}/api/v1/scans/${data.scan_id}/report`,
        undefined,
        30000,
      )
      const reportData = await reportResponse.json()
      if (!reportResponse.ok) throw Error(reportData.detail || 'Could not load the report')
      setReport(reportData)
    } catch (e: any) {
      setError(
        e.name === 'AbortError'
          ? 'The upload or analysis timed out. Please try again.'
          : e.message || 'Something went wrong.',
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <main>
      <header>
        <div className="brand">
          <span className="mark">✓</span> TrustScan
        </div>
        <nav>
          <a href="#how">How it works</a>
          <a href="#privacy">Privacy</a>
        </nav>
      </header>

      <section className="hero">
        <div className="heroCopy">
          <div className="eyebrow">SECURITY, EXPLAINED SIMPLY</div>
          <h1>
            Know before
            <br />
            <em>you open.</em>
          </h1>
          <p>
            Analyze an app and understand what it can access, what static risks were found, and what deserves your attention.
          </p>

          <div className="typeGrid">
            {types.map(([name, desc, state, icon]) => (
              <div className={`typeCard ${state}`} key={name}>
                <div className="typeIcon">
                  <TypeIcon name={icon} />
                </div>
                <div>
                  <b>{name}</b>
                  <span>{desc}</span>
                </div>
                <small>{state === 'available' ? 'Available' : 'Coming soon'}</small>
              </div>
            ))}
          </div>

          <div className="uploadPanel">
            <div className="panelTop">
              <div>
                <b>Analyze Android APK</b>
                <span>Static analysis only · Max 50 MB</span>
              </div>
              <span className="online">● Engine online</span>
            </div>

            <div className="actions">
              <label className="upload">
                <span className="uploadIcon"><UploadIcon /></span>
                {file ? file.name : 'Choose APK'}
                <input
                  type="file"
                  accept=".apk,application/vnd.android.package-archive"
                  onChange={(event) => {
                    const selected = event.target.files?.[0] || null
                    setFile(selected)
                    setError('')
                    if (selected && selected.size > 50 * 1024 * 1024) {
                      setError('APK must be 50 MB or smaller.')
                      setFile(null)
                    }
                  }}
                />
              </label>
              <button disabled={!file || busy} onClick={analyze}>
                {busy ? 'Analyzing…' : 'Analyze APK'}
              </button>
            </div>
            <small>Your file is treated as untrusted and is never executed by the API server.</small>
          </div>
        </div>
      </section>

      {error && <div className="error">{error}</div>}
      {scan && (
        <section className="status">
          <b>{scan.status}</b>
          <span>Real scan state — no fake progress.</span>
        </section>
      )}

      {report && (
        <section className="report">
          <div className="reporttop">
            <div>
              <div className="eyebrow">ANALYSIS REPORT</div>
              <h2>{report.file.application_name || 'Unknown application'}</h2>
              <p>{report.file.package_name || 'Package unknown'}</p>
            </div>
            <div className="score">
              <strong>{report.risk.score}</strong>
              <span>/100</span>
              <b>{report.risk.level}</b>
            </div>
          </div>

          <div className="summary">
            <b>Quick summary</b>
            <p>{report.risk.summary}</p>
          </div>

          <div className="grid">
            <Card title="What this app requests">
              <ul>
                {report.permissions?.length ? (
                  report.permissions.map((permission: any) => (
                    <li key={permission.permission}>
                      <b>{permission.name}</b>
                      <span>{permission.explanation}</span>
                    </li>
                  ))
                ) : (
                  <li>No requested permissions were extracted.</li>
                )}
              </ul>
            </Card>
            <Card title="What we found">
              {report.findings?.length ? (
                report.findings.map((finding: any) => (
                  <div className="finding" key={finding.title}>
                    <b>{finding.title}</b>
                    <p>{finding.detail}</p>
                  </div>
                ))
              ) : (
                <p>No suspicious static indicators were identified by the current rules.</p>
              )}
            </Card>
            <Card title="Unknown">
              <ul>
                {(report.unknown || []).map((item: string) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </Card>
          </div>

          <details>
            <summary>Technical details</summary>
            <pre>{JSON.stringify(report.file, null, 2)}</pre>
          </details>
          <div className="recommend">
            <b>Recommendation</b>
            <p>{report.recommendation}</p>
          </div>
        </section>
      )}

      <section id="how" className="how">
        <div>
          <div className="eyebrow">THE TRUSTSCAN PROMISE</div>
          <h2>
            Security findings,
            <br />
            <em>without the fear.</em>
          </h2>
        </div>
        <div>
          <p>
            TrustScan does not turn a permission into a malware verdict. Static analysis tells us what is declared or embedded in the APK; it cannot prove what happens at runtime.
          </p>
          <p>URLs, dynamic sandboxing and other file types are shown as future capabilities only.</p>
          <div className="shield">
            <div className="shieldicon"><ShieldIcon /></div>
            <div className="shieldText">
              <b>Evidence first</b>
              <p>Facts are separated from interpretation. Unknown stays unknown.</p>
              <span>No malware verdicts from permissions alone.</span>
            </div>
          </div>
        </div>
      </section>

      <footer id="privacy">TrustScan MVP · Static APK analysis · No guarantee of safety · Evidence can be incomplete</footer>
    </main>
  )
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return <div className="card"><h3>{title}</h3>{children}</div>
}

function TypeIcon({ name }: { name: string }) {
  if (name === 'android') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M7.5 8.5h9a2 2 0 0 1 2 2v6.5a1 1 0 0 1-2 0v-5.5h-.8v8a1 1 0 0 1-2 0v-8h-3.4v8a1 1 0 0 1-2 0v-8h-.8V17a1 1 0 0 1-2 0v-6.5a2 2 0 0 1 2-2Z" />
        <path d="m8 7 1.3-2m6.7 2-1.3-2M9 5.5h6" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        <circle cx="9.5" cy="10.8" r=".65" fill="currentColor" />
        <circle cx="14.5" cy="10.8" r=".65" fill="currentColor" />
      </svg>
    )
  }

  if (name === 'url') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M7 17 17 7m-7 0h7v7" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    )
  }

  if (name === 'windows') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M3 5.2 11 4v7H3V5.2Zm10-1.4L21 2.7V11h-8V3.8ZM3 13h8v7l-8-1.2V13Zm10 0h8v8.3L13 20V13Z" />
      </svg>
    )
  }

  if (name === 'document' || name === 'office') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M6.5 3.5h8l3 3v14h-11v-17Z" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
        <path d="M14.5 3.8v3h3M9 11h6M9 14.5h6M9 18h4" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </svg>
    )
  }

  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4 7.5h16v11H4v-11Zm0 0 2.5-3h7l2.2 3" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
    </svg>
  )
}

function UploadIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 16V5m0 0L8 9m4-4 4 4M5 13v6h14v-6" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 32 36" aria-hidden="true">
      <path d="M16 2 27 7v9c0 8-4.7 13.7-11 18-6.3-4.3-11-10-11-18V7l11-5Z" />
      <path d="m10.5 18 3.3 3.3 7.5-8" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
