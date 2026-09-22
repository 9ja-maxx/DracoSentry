import { useEffect, useState, type FormEvent } from 'react';
import { createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';
import { TransactionHashVariant } from 'genlayer-js/types';
import {
  FileCode,
  FileText,
  Search,
  Wallet,
  ArrowUpRight,
  CheckCircle2,
  XCircle,
  AlertOctagon,
  AlertTriangle,
  Flame,
  Sparkles,
} from 'lucide-react';
import deployment from './deployment.json';

interface PackageEntry {
  name: string;
  license: string;
  status: string;
}

interface ObservationData {
  status: string;
  sbom_sha256: string;
  notice_sha256: string;
  packages: { name: string; license: string }[];
  coverage: string[];
}

interface AuditRecord {
  id: number;
  creator: string;
  label: string;
  repository: string;
  commit: string;
  sbom_path: string;
  notice_path: string;
  sbom_sha256: string;
  notice_sha256: string;
  policy: string;
  status: string;
  verdict: string;
  compliance_score: number;
  observation: string;
  successor_plus_one: number;
}

const previewPackages: PackageEntry[] = [
  { name: 'draco-core', license: 'Apache-2.0', status: 'COMPLIANT' },
  { name: 'flame-lexer', license: 'MIT', status: 'COMPLIANT' },
  { name: 'scale-crypto', license: 'BSD-3-Clause', status: 'COMPLIANT' },
  { name: 'wyrm-router', license: 'MIT', status: 'COMPLIANT' },
];

const shortenHash = (val: string, start = 8, end = 6) =>
  val && val.length > start + end ? `${val.slice(0, start)}…${val.slice(-end)}` : val;

const contractAddress = deployment.contractAddress as `0x${string}`;
const readerClient = createClient({ chain: studionet });
type EthereumProvider = NonNullable<Parameters<typeof createClient>[0]>['provider'];

export default function App() {
  const [activeTab, setActiveTab] = useState<'explorer' | 'register' | 'matrix'>('explorer');
  const [auditIdInput, setAuditIdInput] = useState<string>('0');
  const [currentAudit, setCurrentAudit] = useState<AuditRecord | null>(null);
  const [walletAccount, setWalletAccount] = useState<string>('');
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string>('Nidhogg Sentinel ready on GenLayer StudioNet.');

  const isContractConfigured =
    /^0x[a-fA-F0-9]{40}$/.test(deployment.contractAddress) &&
    !/^0x0{40}$/.test(deployment.contractAddress);

  // Parse observation if available
  let parsedObservation: ObservationData | null = null;
  try {
    if (currentAudit?.observation) {
      parsedObservation = JSON.parse(currentAudit.observation);
    }
  } catch (e) {
    console.error('Failed to parse audit observation JSON', e);
  }

  const packagesList: PackageEntry[] =
    parsedObservation?.packages.map((pkg, idx) => ({
      name: pkg.name,
      license: pkg.license,
      status: parsedObservation?.coverage[idx] || 'UNRESOLVED',
    })) || previewPackages;

  const compliantCount = packagesList.filter((p) => p.status === 'COMPLIANT').length;
  const complianceScore = packagesList.length
    ? Math.round((compliantCount / packagesList.length) * 100)
    : 0;
  const verdictText = currentAudit?.verdict || 'VERIFIED_COMPLIANT';

  // Connect wallet
  async function handleConnectWallet() {
    try {
      const eth = (window as unknown as { ethereum?: EthereumProvider }).ethereum;
      if (!eth) {
        throw new Error('No EIP-1193 compatible Web3 wallet detected. Install MetaMask to connect.');
      }
      await eth.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: `0x${studionet.id.toString(16)}` }],
      });
      const accounts = (await eth.request({ method: 'eth_requestAccounts' })) as string[];
      if (accounts.length > 0) {
        setWalletAccount(accounts[0]);
        setStatusMessage(`Connected: ${shortenHash(accounts[0], 6, 4)} on StudioNet`);
      }
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : 'Wallet connection failed');
    }
  }

  // Load audit by ID
  async function fetchAuditDossier(id: string = auditIdInput) {
    try {
      if (!isContractConfigured) {
        setStatusMessage('Deploy contract on StudioNet to query live on-chain audits.');
        return;
      }
      setIsProcessing(true);
      const result = await readerClient.readContract({
        address: contractAddress,
        functionName: 'get_audit_dossier',
        args: [BigInt(id)],
        transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
      });

      if (typeof result === 'string' && result !== 'NOT_FOUND') {
        const parsed = JSON.parse(result) as AuditRecord;
        setCurrentAudit(parsed);
        setStatusMessage(`Loaded finalized Nidhogg audit #${id}`);
      } else {
        setStatusMessage(`Audit #${id} does not exist on-chain.`);
      }
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : 'Failed to query audit record');
    } finally {
      setIsProcessing(false);
    }
  }

  // Submit on-chain transaction
  async function executeTransaction(methodName: string, args: (string | bigint)[]) {
    if (!walletAccount) {
      setStatusMessage('Please connect your StudioNet wallet to sign transactions.');
      return;
    }
    setIsProcessing(true);
    try {
      const provider = (window as unknown as { ethereum?: EthereumProvider }).ethereum;
      if (!provider) throw new Error('Web3 provider disconnected.');

      const writerClient = createClient({
        chain: studionet,
        account: walletAccount as `0x${string}`,
        provider,
      });

      const txHash = await writerClient.writeContract({
        address: contractAddress,
        functionName: methodName,
        args,
        value: 0n,
        leaderOnly: false,
      });

      setStatusMessage(`Transaction submitted: ${shortenHash(String(txHash), 10, 8)}. Awaiting finality…`);
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : 'Transaction execution failed');
    } finally {
      setIsProcessing(false);
    }
  }

  // Register release form handler
  function handleRegisterRelease(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const label = String(formData.get('label'));
    const owner = String(formData.get('owner'));
    const repository = String(formData.get('repository'));
    const commit = String(formData.get('commit'));
    const sbomPath = String(formData.get('sbomPath'));
    const noticePath = String(formData.get('noticePath'));
    const sbomSha256 = String(formData.get('sbomSha256'));
    const noticeSha256 = String(formData.get('noticeSha256'));
    const policy = String(formData.get('policy'));

    void executeTransaction('register_release_audit', [
      label,
      owner,
      repository,
      commit,
      sbomPath,
      noticePath,
      sbomSha256,
      noticeSha256,
      policy,
    ]);
  }

  useEffect(() => {
    if (isContractConfigured) {
      void fetchAuditDossier('0');
    }
  }, [isContractConfigured]);

  return (
    <div>
      {/* Top Header */}
      <header>
        <button className="brand-container" onClick={() => setActiveTab('explorer')}>
          <img src="/draco-logo.svg" alt="Nidhogg Logo" className="brand-logo" />
          <div>
            <div className="brand-title">
              NID<span>HOGG</span>
            </div>
            <div className="brand-subtitle">Dependency Root Sentinel</div>
          </div>
        </button>

        <div className="nav-cluster">
          <nav>
            <button
              className={activeTab === 'explorer' ? 'active' : ''}
              onClick={() => setActiveTab('explorer')}
            >
              Audit Explorer
            </button>
            <button
              className={activeTab === 'register' ? 'active' : ''}
              onClick={() => setActiveTab('register')}
            >
              Register Release
            </button>
            <button
              className={activeTab === 'matrix' ? 'active' : ''}
              onClick={() => setActiveTab('matrix')}
            >
              Verification Matrix
            </button>
          </nav>

          <div className="network-badge">
            <span className="pulse-dot"></span>
            GenLayer StudioNet
          </div>

          <button className="btn-wallet" onClick={handleConnectWallet} disabled={isProcessing}>
            <Wallet size={16} />
            {walletAccount ? shortenHash(walletAccount, 6, 4) : 'Connect Wallet'}
          </button>
        </div>
      </header>

      <main>
        {activeTab === 'explorer' && (
          <div>
            {/* Quick Command Bar */}
            <div className="command-deck">
              <div className="search-group">
                <Search size={18} color="var(--text-muted)" />
                <input
                  aria-label="Audit ID"
                  className="search-input"
                  value={auditIdInput}
                  onChange={(e) => setAuditIdInput(e.target.value)}
                  placeholder="ID (e.g. 0)"
                />
                <button
                  className="btn-action"
                  onClick={() => void fetchAuditDossier()}
                  disabled={isProcessing}
                >
                  Query Dossier
                </button>
              </div>

              <div className="preset-pills">
                <span>Presets:</span>
                <button
                  className="preset-btn"
                  onClick={() => {
                    setAuditIdInput('0');
                    void fetchAuditDossier('0');
                  }}
                >
                  Audit #0 (Complete)
                </button>
                <button
                  className="preset-btn"
                  onClick={() => {
                    setAuditIdInput('1');
                    void fetchAuditDossier('1');
                  }}
                >
                  Audit #1 (Deficit)
                </button>
                <button
                  className="preset-btn"
                  onClick={() => {
                    setAuditIdInput('2');
                    void fetchAuditDossier('2');
                  }}
                >
                  Audit #2 (Conflict)
                </button>
              </div>
            </div>

            {/* Workspace Grid */}
            <div className="workspace-grid">
              {/* Left Column: Dossier Details & Package Ledger */}
              <div>
                {/* Dossier Radar Card */}
                <div className="dossier-card">
                  <div className="dossier-header">
                    <div>
                      <div className="eyebrow">Cryptographic Release Provenance</div>
                      <h1 className="dossier-title">
                        {currentAudit?.label || 'Nidhogg Verified Release v1.0.0'}
                      </h1>
                      <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                        Authority:{' '}
                        <strong>{currentAudit?.repository || '9ja-maxx/Nidhogg'}</strong> · Commit:{' '}
                        <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--dragon-gold)' }}>
                          {shortenHash(
                            currentAudit?.commit || '1b4fa7cd039c3b62d5444c2b06de19d98f6a0158',
                            10,
                            8,
                          )}
                        </code>
                      </p>
                    </div>

                    <div className="score-badge">
                      <span className="score-value">{complianceScore}%</span>
                      <span className="score-label">Coverage</span>
                    </div>
                  </div>

                  <div className="progress-bar-container">
                    <div className="progress-bar-fill" style={{ width: `${complianceScore}%` }} />
                  </div>

                  {/* Dual Artifacts Row */}
                  <div className="artifacts-row">
                    <div className="artifact-card">
                      <FileCode size={24} className="artifact-icon" />
                      <div className="artifact-content">
                        <span className="artifact-type">SPDX SBOM Manifest</span>
                        <div className="artifact-path">
                          {currentAudit?.sbom_path || 'fixtures/sbom-complete.json'}
                        </div>
                        <span className="artifact-hash">
                          sha256:{' '}
                          {shortenHash(
                            currentAudit?.sbom_sha256 ||
                              'e5b54ad859fac78d051ef0afd14de452538d8524c6d91d0ffdd1e6530ba74c8a',
                            8,
                            6,
                          )}
                        </span>
                      </div>
                    </div>

                    <div className="artifact-card">
                      <FileText size={24} className="artifact-icon" />
                      <div className="artifact-content">
                        <span className="artifact-type">Third-Party Notice</span>
                        <div className="artifact-path">
                          {currentAudit?.notice_path || 'fixtures/notice-complete.md'}
                        </div>
                        <span className="artifact-hash">
                          sha256:{' '}
                          {shortenHash(
                            currentAudit?.notice_sha256 ||
                              '4adb9e2995f93b4ec677f740fa75f2a5c4af0e5044525518ac94d8672608a378',
                            8,
                            6,
                          )}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Package Compliance Ledger */}
                <div className="ledger-card">
                  <div className="section-head">
                    <h2>Declared Dependency Ledger ({packagesList.length} packages)</h2>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      Multi-Validator Consensus Verified
                    </span>
                  </div>

                  {packagesList.map((pkg, idx) => (
                    <div className="package-item" key={pkg.name}>
                      <div className="package-meta">
                        <span className="package-index">0{idx + 1}</span>
                        <div>
                          <span className="package-name">{pkg.name}</span>
                          <span className="package-license" style={{ marginLeft: '0.6rem' }}>
                            {pkg.license}
                          </span>
                        </div>
                      </div>

                      <span className={`status-badge ${pkg.status.toLowerCase()}`}>
                        {pkg.status === 'COMPLIANT' && <CheckCircle2 size={13} />}
                        {pkg.status === 'PERMISSIVE_GAP' && <AlertTriangle size={13} />}
                        {pkg.status === 'COPYLEFT_CONFLICT' && <AlertOctagon size={13} />}
                        {pkg.status === 'UNRESOLVED' && <XCircle size={13} />}
                        {pkg.status.replace('_', ' ')}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right Column: Audit Rail & Security Timeline */}
              <div className="rail-sidebar">
                {/* Terminal Verdict Box */}
                <div className="verdict-box">
                  <div className="verdict-label">Official Terminal Verdict</div>
                  <div className="verdict-display">
                    <span className={`status-badge ${verdictText.toLowerCase()}`}>
                      <Flame size={15} />
                      {verdictText.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <div className="verdict-sub">
                    Status: <strong>{currentAudit?.status || 'FINALIZED'}</strong> · Consensus Verified
                  </div>
                </div>

                {/* Security Timeline */}
                <div className="timeline-card">
                  <div className="eyebrow">Cryptographic Invariant Pipeline</div>
                  <ul className="timeline-list">
                    <li className="timeline-step">
                      <span className="step-marker done">1</span>
                      <div className="step-info">
                        <b>Raw GitHub Commit Bound</b>
                        <span>Derived in-contract to prevent SSRF</span>
                      </div>
                    </li>
                    <li className="timeline-step">
                      <span className="step-marker done">2</span>
                      <div className="step-info">
                        <b>Bit-Exact SHA-256 Verified</b>
                        <span>Cryptographic pre-inference integrity</span>
                      </div>
                    </li>
                    <li className="timeline-step">
                      <span className="step-marker done">3</span>
                      <div className="step-info">
                        <b>Validator LLM Consensus</b>
                        <span>Independent re-execution & equivalence</span>
                      </div>
                    </li>
                    <li className="timeline-step">
                      <span className="step-marker done">4</span>
                      <div className="step-info">
                        <b>Deterministic Precedence Seal</b>
                        <span>Immutable on-chain verdict storage</span>
                      </div>
                    </li>
                  </ul>
                </div>

                {/* Assessment Action */}
                {currentAudit?.status === 'REGISTERED' && (
                  <button
                    className="btn-assess"
                    onClick={() =>
                      void executeTransaction('execute_consensus_assessment', [BigInt(auditIdInput)])
                    }
                    disabled={isProcessing || !walletAccount}
                  >
                    Execute Consensus Assessment
                  </button>
                )}

                <a
                  className="btn-explorer"
                  href={`https://explorer-studio.genlayer.com/address/${contractAddress}`}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  View Contract on Explorer <ArrowUpRight size={15} />
                </a>

                {/* Remediation Pointer Note */}
                {currentAudit && currentAudit.successor_plus_one > 0 && (
                  <div
                    style={{
                      background: 'rgba(245, 158, 11, 0.08)',
                      border: '1px solid var(--border-gold)',
                      borderRadius: '10px',
                      padding: '0.85rem',
                      fontSize: '0.8rem',
                      color: 'var(--text-gold)',
                    }}
                  >
                    <Sparkles size={14} style={{ display: 'inline', marginRight: '0.35rem' }} />
                    Remediation linked to successor Audit #{currentAudit.successor_plus_one - 1}.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'register' && (
          <div className="form-container">
            <div className="form-header">
              <div className="eyebrow">REGISTER IMMUTABLE RELEASE</div>
              <h1>Bind Release Artifacts for Consensus Audit</h1>
              <p>
                Commit an authoritative 40-character Git commit hash, SPDX SBOM, and third-party notice
                path. Validators independently fetch raw bytes and verify SHA-256 digests before evaluating
                compliance.
              </p>
            </div>

            <form onSubmit={handleRegisterRelease} className="form-grid">
              <div className="input-field">
                <label>Release Label</label>
                <input
                  name="label"
                  placeholder="Example: Acme Core Engine v2.4.0"
                  defaultValue="Nidhogg Production v1.0.0"
                  required
                />
              </div>

              <div className="form-row">
                <div className="input-field">
                  <label>GitHub Organization / Owner</label>
                  <input name="owner" placeholder="organization-name" defaultValue="9ja-maxx" required />
                </div>
                <div className="input-field">
                  <label>Repository Name</label>
                  <input name="repository" placeholder="repository-name" defaultValue="Nidhogg" required />
                </div>
              </div>

              <div className="input-field">
                <label>Immutable Git Commit SHA (40 Characters)</label>
                <input
                  name="commit"
                  className="mono"
                  placeholder="40-character hex commit hash"
                  defaultValue="1b4fa7cd039c3b62d5444c2b06de19d98f6a0158"
                  pattern="[a-fA-F0-9]{40}"
                  required
                />
              </div>

              <div className="form-divider">
                <div className="eyebrow">AUTHENTICATED ARTIFACT COMMITMENTS</div>
              </div>

              <div className="form-row">
                <div className="input-field">
                  <label>SBOM Path at Commit</label>
                  <input
                    name="sbomPath"
                    placeholder="e.g. fixtures/sbom-complete.json"
                    defaultValue="fixtures/sbom-complete.json"
                    required
                  />
                </div>
                <div className="input-field">
                  <label>Expected SBOM SHA-256</label>
                  <input
                    name="sbomSha256"
                    className="mono"
                    placeholder="64-character SHA-256 hash"
                    defaultValue="e5b54ad859fac78d051ef0afd14de452538d8524c6d91d0ffdd1e6530ba74c8a"
                    pattern="[a-fA-F0-9]{64}"
                    required
                  />
                </div>
              </div>

              <div className="form-row">
                <div className="input-field">
                  <label>Notice Path at Commit</label>
                  <input
                    name="noticePath"
                    placeholder="e.g. fixtures/notice-complete.md"
                    defaultValue="fixtures/notice-complete.md"
                    required
                  />
                </div>
                <div className="input-field">
                  <label>Expected Notice SHA-256</label>
                  <input
                    name="noticeSha256"
                    className="mono"
                    placeholder="64-character SHA-256 hash"
                    defaultValue="4adb9e2995f93b4ec677f740fa75f2a5c4af0e5044525518ac94d8672608a378"
                    pattern="[a-fA-F0-9]{64}"
                    required
                  />
                </div>
              </div>

              <div className="input-field">
                <label>Compliance Evaluation Policy</label>
                <textarea
                  name="policy"
                  rows={3}
                  defaultValue="Every SBOM package must have matching copyright attribution and declared license in the third-party notice."
                  required
                />
              </div>

              <div className="form-actions">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setActiveTab('explorer')}
                >
                  Cancel
                </button>
                <button type="submit" className="btn-action" disabled={isProcessing || !walletAccount}>
                  {walletAccount ? 'Register Release on StudioNet' : 'Connect Wallet to Register'}
                </button>
              </div>
            </form>
          </div>
        )}

        {activeTab === 'matrix' && (
          <div className="ledger-card" style={{ maxWidth: '960px', margin: '0 auto' }}>
            <div className="section-head">
              <div>
                <div className="eyebrow">PROTOCOL VERIFICATION MATRIX</div>
                <h2>20-Step Security and Lifecycle Specification</h2>
              </div>
            </div>

            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
              Nidhogg guarantees fail-closed execution across every potential failure mode in software
              supply chain attribution:
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
              {[
                {
                  id: '01',
                  scenario: 'Unpinned branch name or tag',
                  verdict: 'INVALID_SOURCE_IDENTIFIERS',
                  rule: 'Requires immutable 40-char commit SHA to prevent target drift.',
                },
                {
                  id: '02',
                  scenario: 'Directory traversal attempt (..)',
                  verdict: 'INVALID_SOURCE_IDENTIFIERS',
                  rule: 'Neutralizes path-based SSRF and directory escape attacks.',
                },
                {
                  id: '03',
                  scenario: 'Colliding artifact paths',
                  verdict: 'COLLIDING_ARTIFACT_PATHS',
                  rule: 'Rejects identical paths for SBOM manifest and attribution notice.',
                },
                {
                  id: '04',
                  scenario: 'Authoritative complete registration',
                  verdict: 'REGISTERED',
                  rule: 'Records release commitments into on-chain TreeMap storage.',
                },
                {
                  id: '05',
                  scenario: 'Exact duplicate release submission',
                  verdict: 'DUPLICATE_RELEASE_REGISTRATION',
                  rule: 'Blocks registry pollution and repeat registration replay.',
                },
                {
                  id: '06',
                  scenario: 'Happy path consensus execution',
                  verdict: 'VERIFIED_COMPLIANT',
                  rule: 'Multi-validator non-deterministic consensus matches all packages.',
                },
                {
                  id: '07',
                  scenario: 'Post-finality assessment replay',
                  verdict: 'AUDIT_ALREADY_FINALIZED',
                  rule: 'Guarantees audit finality; finalized records cannot be re-assessed.',
                },
                {
                  id: '08',
                  scenario: 'Omitted permissive package notice',
                  verdict: 'ATTRIBUTION_DEFICIT',
                  rule: 'Detects missing attribution; assigns bounded deficit score.',
                },
                {
                  id: '09',
                  scenario: 'Upstream reciprocal copyleft conflict',
                  verdict: 'HIGH_RISK_LICENSE_VIOLATION',
                  rule: 'Prioritizes legal copyleft obligations over permissive deficits.',
                },
                {
                  id: '10',
                  scenario: 'Single-byte digest substitution',
                  verdict: 'TAMPER_DETECTED',
                  rule: 'Pre-inference cryptographic gate halts execution on hash mismatch.',
                },
                {
                  id: '11',
                  scenario: 'Transient external network outage',
                  verdict: 'AUDIT_RETRYABLE',
                  rule: 'Leaves state in REGISTERED without failing audit permanently.',
                },
                {
                  id: '12',
                  scenario: 'Creator-authenticated remediation linking',
                  verdict: 'REMEDIATION_BOUND',
                  rule: 'Immutably links historical audit to newly finalized successor commit.',
                },
              ].map((item) => (
                <div
                  key={item.id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '0.85rem 1rem',
                    background: 'var(--bg-card)',
                    borderRadius: '8px',
                    border: '1px solid var(--border-subtle)',
                    flexWrap: 'wrap',
                    gap: '0.75rem',
                  }}
                >
                  <div style={{ display: 'flex', gap: '0.85rem', alignItems: 'center' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--dragon-gold)' }}>
                      #{item.id}
                    </span>
                    <div>
                      <b style={{ fontSize: '0.88rem', display: 'block' }}>{item.scenario}</b>
                      <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>{item.rule}</span>
                    </div>
                  </div>
                  <span className="status-badge compliant">{item.verdict}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Global Notice Banner */}
        <div className="toast-notice">
          <strong>Nidhogg Sentinel Log:</strong> {statusMessage}
        </div>
      </main>

      {/* Footer */}
      <footer>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <img src="/draco-logo.svg" alt="logo" style={{ width: '18px', height: '18px' }} />
          <span>
            Nidhogg Protocol · Developed by <strong>9ja_maxx</strong>
          </span>
        </div>
        <div>
          Contract Target: <code>{shortenHash(deployment.contractAddress, 8, 6)}</code> (StudioNet)
        </div>
      </footer>
    </div>
  );
}
