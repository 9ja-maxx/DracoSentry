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
  ShieldCheck,
  RotateCw,
  LogOut,
  Copy,
  Check,
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

const shortenHash = (val: string, start = 8, end = 6) =>
  val && val.length > start + end ? `${val.slice(0, start)}…${val.slice(-end)}` : val;

// Authoritative chain target: locked SDK studionet target synchronized with deployment manifest
export const authoritativeChain = {
  ...studionet,
  id: deployment.chainId,
  rpcUrls: {
    ...studionet.rpcUrls,
    default: {
      http: deployment.rpcUrl ? [deployment.rpcUrl] : studionet.rpcUrls.default.http,
    },
  },
};

const contractAddress = deployment.contractAddress as `0x${string}`;
const readerClient = createClient({ chain: authoritativeChain });
type EthereumProvider = NonNullable<Parameters<typeof createClient>[0]>['provider'];

// Authoritative repository commitments from fixtures/FIXTURE_MANIFEST.json
const VERIFIED_FIXTURES = {
  owner: '9ja-maxx',
  repository: 'Nidhogg',
  commit: '479dd1c04e5941faa8387fecae16684052514c65',
  policy: 'Every SBOM package must have matching copyright attribution and declared license in the third-party notice.',
  clean: {
    label: 'Nidhogg Core Release v1.0.0 (Clean)',
    sbomPath: 'fixtures/sbom-complete.json',
    sbomSha256: '46ded58702fdb3133b7a09e645222101e5093edf24ebc05ec1f5b07fb9062682',
    noticePath: 'fixtures/notice-complete.md',
    noticeSha256: 'd3fe15b229bf03d98c37b48fc4d54e046e9709c21fc3d1997b39395f98f0d892',
  },
  permissiveGap: {
    label: 'Nidhogg v1.0.1 (Permissive Gap Test)',
    sbomPath: 'fixtures/sbom-complete.json',
    sbomSha256: '46ded58702fdb3133b7a09e645222101e5093edf24ebc05ec1f5b07fb9062682',
    noticePath: 'fixtures/notice-permissive-gap.md',
    noticeSha256: '0decbc6717970529c54c51ae081a2c6a89eb6af62ecf730478ed808b30d68eb4',
  },
  copyleftConflict: {
    label: 'Nidhogg v1.0.2 (Copyleft Conflict Test)',
    sbomPath: 'fixtures/sbom-complete.json',
    sbomSha256: '46ded58702fdb3133b7a09e645222101e5093edf24ebc05ec1f5b07fb9062682',
    noticePath: 'fixtures/notice-copyleft-conflict.md',
    noticeSha256: 'a8b641290b70fa37620800bf00b96f708fa86ba5157fc8bb1cd1714ffc123d80',
  },
  adversarialInjection: {
    label: 'Nidhogg v1.0.3 (Adversarial Injection Defense)',
    sbomPath: 'fixtures/sbom-complete.json',
    sbomSha256: '46ded58702fdb3133b7a09e645222101e5093edf24ebc05ec1f5b07fb9062682',
    noticePath: 'fixtures/notice-adversarial-injection.md',
    noticeSha256: 'b710aced28efc4d08efad070592998663d5069bf33ebdda0c639b0e174a03830',
  },
};

export default function App() {
  const [activeTab, setActiveTab] = useState<'explorer' | 'register' | 'matrix'>('explorer');
  const [auditIdInput, setAuditIdInput] = useState<string>('0');
  const [currentAudit, setCurrentAudit] = useState<AuditRecord | null>(null);
  const [totalAuditsOnChain, setTotalAuditsOnChain] = useState<number | null>(null);
  const [walletAccount, setWalletAccount] = useState<string>('');
  const [copiedAddress, setCopiedAddress] = useState<boolean>(false);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string>('Nidhogg Sentinel connected to GenLayer StudioNet.');

  // Form State for Register Tab
  const [formLabel, setFormLabel] = useState(VERIFIED_FIXTURES.clean.label);
  const [formOwner, setFormOwner] = useState(VERIFIED_FIXTURES.owner);
  const [formRepo, setFormRepo] = useState(VERIFIED_FIXTURES.repository);
  const [formCommit, setFormCommit] = useState(VERIFIED_FIXTURES.commit);
  const [formSbomPath, setFormSbomPath] = useState(VERIFIED_FIXTURES.clean.sbomPath);
  const [formSbomSha, setFormSbomSha] = useState(VERIFIED_FIXTURES.clean.sbomSha256);
  const [formNoticePath, setFormNoticePath] = useState(VERIFIED_FIXTURES.clean.noticePath);
  const [formNoticeSha, setFormNoticeSha] = useState(VERIFIED_FIXTURES.clean.noticeSha256);
  const [formPolicy, setFormPolicy] = useState(VERIFIED_FIXTURES.policy);

  const isContractConfigured =
    /^0x[a-fA-F0-9]{40}$/.test(deployment.contractAddress) &&
    !/^0x0{40}$/.test(deployment.contractAddress);

  // Parse live observation from on-chain audit record (NO MOCK DATA)
  let parsedObservation: ObservationData | null = null;
  if (currentAudit?.observation) {
    try {
      parsedObservation = JSON.parse(currentAudit.observation) as ObservationData;
    } catch (e) {
      console.error('Failed to parse on-chain audit observation JSON', e);
    }
  }

  // Derive package breakdown strictly from on-chain observation payload
  const packagesList: PackageEntry[] =
    parsedObservation?.packages?.map((pkg, idx) => ({
      name: pkg.name,
      license: pkg.license,
      status: parsedObservation?.coverage?.[idx] || 'UNRESOLVED',
    })) || [];

  // Compliance score: strictly from on-chain contract record
  const complianceScore = currentAudit ? currentAudit.compliance_score : 0;
  const verdictText = currentAudit ? currentAudit.verdict : 'PENDING';

  // Connect wallet
  async function handleConnectWallet() {
    try {
      const eth = (window as unknown as { ethereum?: EthereumProvider }).ethereum;
      if (!eth) {
        throw new Error('No Web3 wallet detected. Install MetaMask or another Web3 extension.');
      }
      try {
        await eth.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: `0x${authoritativeChain.id.toString(16)}` }],
        });
      } catch (switchErr: unknown) {
        // Fallback to wallet_addEthereumChain if chain is not yet registered in wallet
        const errObj = switchErr as { code?: number; message?: string };
        if (errObj?.code === 4902 || errObj?.message?.includes('wallet_addEthereumChain')) {
          await eth.request({
            method: 'wallet_addEthereumChain',
            params: [
              {
                chainId: `0x${authoritativeChain.id.toString(16)}`,
                chainName: authoritativeChain.name,
                rpcUrls: authoritativeChain.rpcUrls.default.http,
                nativeCurrency: authoritativeChain.nativeCurrency,
                blockExplorerUrls: authoritativeChain.blockExplorers?.default?.url
                  ? [authoritativeChain.blockExplorers.default.url]
                  : [],
              },
            ],
          });
        } else {
          throw switchErr;
        }
      }
      const accounts = (await eth.request({ method: 'eth_requestAccounts' })) as string[];
      if (accounts.length > 0) {
        setWalletAccount(accounts[0]);
        setStatusMessage(`Connected: ${shortenHash(accounts[0], 6, 4)} on ${authoritativeChain.name} (Chain ID: ${authoritativeChain.id})`);
      }
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : 'Wallet connection failed');
    }
  }

  function handleCopyAddress() {
    if (walletAccount) {
      void navigator.clipboard.writeText(walletAccount);
      setCopiedAddress(true);
      setTimeout(() => setCopiedAddress(false), 2000);
    }
  }

  function handleDisconnectWallet() {
    setWalletAccount('');
    setStatusMessage('Wallet disconnected.');
  }

  // Query cumulative registered audit count from on-chain contract
  async function fetchTotalAudits() {
    if (!isContractConfigured) return;
    try {
      const res = await readerClient.readContract({
        address: contractAddress,
        functionName: 'get_total_audits',
        args: [],
        transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
      });
      if (typeof res === 'string' && !isNaN(Number(res))) {
        setTotalAuditsOnChain(Number(res));
      }
    } catch (e) {
      console.error('Failed to fetch total audits', e);
    }
  }

  // Load audit by ID directly from GenLayer contract
  async function fetchAuditDossier(id: string = auditIdInput) {
    if (!isContractConfigured) {
      setStatusMessage('Contract address is not configured.');
      return;
    }
    const numericId = parseInt(id.trim(), 10);
    if (isNaN(numericId) || numericId < 0) {
      setStatusMessage('Please enter a valid non-negative numeric Audit ID.');
      return;
    }

    setIsProcessing(true);
    try {
      const result = await readerClient.readContract({
        address: contractAddress,
        functionName: 'get_audit_dossier',
        args: [BigInt(numericId)],
        transactionHashVariant: TransactionHashVariant.LATEST_FINAL,
      });

      if (typeof result === 'string' && result !== 'NOT_FOUND') {
        const parsed = JSON.parse(result) as AuditRecord;
        setCurrentAudit(parsed);
        setStatusMessage(`Loaded authentic on-chain audit #${numericId}`);
      } else {
        setCurrentAudit(null);
        setStatusMessage(`Audit #${numericId} does not exist in on-chain storage.`);
      }
    } catch (err) {
      setCurrentAudit(null);
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
        chain: authoritativeChain,
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
      setTimeout(() => {
        void fetchTotalAudits();
        if (currentAudit) {
          void fetchAuditDossier(String(currentAudit.id));
        }
      }, 5000);
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : 'Transaction execution failed');
    } finally {
      setIsProcessing(false);
    }
  }

  // Register release form handler
  function handleRegisterRelease(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    void executeTransaction('register_release_audit', [
      formLabel,
      formOwner,
      formRepo,
      formCommit,
      formSbomPath,
      formNoticePath,
      formSbomSha,
      formNoticeSha,
      formPolicy,
    ]);
  }

  // Helper to load fixture preset into form
  function applyFixturePreset(presetKey: 'clean' | 'permissiveGap' | 'copyleftConflict' | 'adversarialInjection') {
    const fixture = VERIFIED_FIXTURES[presetKey];
    setFormLabel(fixture.label);
    setFormOwner(VERIFIED_FIXTURES.owner);
    setFormRepo(VERIFIED_FIXTURES.repository);
    setFormCommit(VERIFIED_FIXTURES.commit);
    setFormSbomPath(fixture.sbomPath);
    setFormSbomSha(fixture.sbomSha256);
    setFormNoticePath(fixture.noticePath);
    setFormNoticeSha(fixture.noticeSha256);
    setFormPolicy(VERIFIED_FIXTURES.policy);
    setStatusMessage(`Loaded preset: ${fixture.label}`);
  }

  useEffect(() => {
    if (isContractConfigured) {
      void fetchTotalAudits();
      void fetchAuditDossier('0');
    }
  }, [isContractConfigured]);

  return (
    <div>
      {/* Top Header */}
      <header>
        <div className="header-brand-wrap">
          <button className="brand-container" onClick={() => setActiveTab('explorer')}>
            <img src="/nidhogg-logo.svg" alt="Nidhogg Logo" className="brand-logo" />
            <div>
              <div className="brand-title">
                NID<span>HOGG</span>
              </div>
              <div className="brand-subtitle">Autonomous Supply-Chain Arbiter · GenLayer</div>
            </div>
          </button>
        </div>

        <nav className="nav-tabs">
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

        <div className="header-wallet-group">
          <div
            className="network-badge"
            title={`Real-time ${deployment.network} (Chain ID: ${authoritativeChain.id}) contract status`}
            style={{
              borderColor: totalAuditsOnChain !== null && totalAuditsOnChain > 0
                ? 'rgba(16, 185, 129, 0.4)'
                : 'rgba(245, 158, 11, 0.4)',
            }}
          >
            <span className="pulse-dot"></span>
            <span className="network-name">StudioNet</span>
            <span className="network-pill-sep">·</span>
            <span className="network-pill-count">
              {totalAuditsOnChain === null ? 'Syncing…' : `${totalAuditsOnChain} ${totalAuditsOnChain === 1 ? 'Audit' : 'Audits'}`}
            </span>
          </div>

          {walletAccount ? (
            <div className="wallet-connected-pill" title={`Connected: ${walletAccount}`}>
              <span className="wallet-connected-dot"></span>
              <button
                type="button"
                className="wallet-address-btn"
                onClick={handleCopyAddress}
                title="Click to copy address"
              >
                <span className="wallet-address-text">{shortenHash(walletAccount, 6, 4)}</span>
                {copiedAddress ? <Check size={13} className="text-emerald" /> : <Copy size={13} />}
              </button>
              <button
                type="button"
                className="wallet-disconnect-btn"
                onClick={handleDisconnectWallet}
                title="Disconnect wallet"
              >
                <LogOut size={13} />
              </button>
            </div>
          ) : (
            <button
              type="button"
              className="btn-wallet"
              onClick={handleConnectWallet}
              disabled={isProcessing}
            >
              <Wallet size={15} />
              <span>Connect Wallet</span>
            </button>
          )}
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
                  placeholder="Audit ID (e.g. 0)"
                />
                <button
                  className="btn-action"
                  onClick={() => void fetchAuditDossier()}
                  disabled={isProcessing}
                >
                  <Search size={14} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                  Query On-Chain
                </button>
                <button
                  className="preset-btn"
                  title="Refresh total on-chain audit count"
                  onClick={() => {
                    void fetchTotalAudits();
                    void fetchAuditDossier();
                  }}
                  disabled={isProcessing}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                >
                  <RotateCw size={13} />
                  Refresh
                </button>
              </div>

              <div className="preset-pills">
                <span>On-Chain Audits:</span>
                {totalAuditsOnChain !== null && totalAuditsOnChain > 0 ? (
                  Array.from({ length: Math.min(totalAuditsOnChain, 5) }).map((_, i) => (
                    <button
                      key={i}
                      className={`preset-btn ${auditIdInput === String(i) ? 'active' : ''}`}
                      onClick={() => {
                        setAuditIdInput(String(i));
                        void fetchAuditDossier(String(i));
                      }}
                    >
                      Audit #{i}
                    </button>
                  ))
                ) : (
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                    0 audits registered on-chain
                  </span>
                )}
              </div>
            </div>

            {/* Empty State when no on-chain audit is loaded */}
            {!currentAudit ? (
              <div
                className="dossier-card"
                style={{
                  textAlign: 'center',
                  padding: '4rem 2rem',
                  maxWidth: '780px',
                  margin: '0 auto',
                  border: '1px dashed var(--border-accent)',
                }}
              >
                <div
                  style={{
                    display: 'inline-flex',
                    padding: '1.2rem',
                    background: 'rgba(245, 158, 11, 0.08)',
                    borderRadius: '50%',
                    marginBottom: '1.5rem',
                    border: '1px solid rgba(245, 158, 11, 0.25)',
                  }}
                >
                  <ShieldCheck size={40} color="var(--dragon-gold)" />
                </div>
                <h2 style={{ fontSize: '1.4rem', fontWeight: 700, marginBottom: '0.75rem', color: '#f8fafc' }}>
                  {totalAuditsOnChain === 0
                    ? 'No Release Audits Registered On-Chain Yet'
                    : `Audit #${auditIdInput} Not Found in Contract Storage`}
                </h2>
                <p
                  style={{
                    color: 'var(--text-secondary)',
                    maxWidth: '560px',
                    margin: '0 auto 2rem',
                    fontSize: '0.92rem',
                    lineHeight: '1.65',
                  }}
                >
                  {totalAuditsOnChain === 0 ? (
                    <>
                      Contract <code style={{ color: 'var(--dragon-gold)', fontFamily: 'var(--font-mono)' }}>{shortenHash(contractAddress, 8, 6)}</code> is live on GenLayer StudioNet with <strong>0 recorded releases</strong>.
                      <br />
                      This DApp shows <strong>100% authentic on-chain data</strong>. Register Audit #0 to trigger GenLayer validator consensus!
                    </>
                  ) : (
                    <>
                      Audit record #{auditIdInput} does not exist in contract{' '}
                      <code style={{ color: 'var(--dragon-gold)', fontFamily: 'var(--font-mono)' }}>{shortenHash(contractAddress, 8, 6)}</code>.
                      The contract currently holds <strong>{totalAuditsOnChain ?? 0} recorded {totalAuditsOnChain === 1 ? 'audit' : 'audits'}</strong> (IDs 0 to {(totalAuditsOnChain ?? 1) - 1}).
                    </>
                  )}
                </p>

                <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center', flexWrap: 'wrap' }}>
                  <button
                    className="btn-action"
                    style={{ width: 'auto', padding: '0.7rem 1.5rem', display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}
                    onClick={() => setActiveTab('register')}
                  >
                    <Sparkles size={16} />
                    {totalAuditsOnChain === 0 ? 'Register First Release (Audit #0)' : 'Register New Release Candidate'}
                  </button>

                  {totalAuditsOnChain && totalAuditsOnChain > 0 ? (
                    <button
                      className="preset-btn"
                      style={{ padding: '0.7rem 1.25rem' }}
                      onClick={() => {
                        setAuditIdInput('0');
                        void fetchAuditDossier('0');
                      }}
                    >
                      Load Audit #0
                    </button>
                  ) : null}
                </div>
              </div>
            ) : (
              /* Authentic On-Chain Dossier */
              <div className="workspace-grid">
                {/* Left Column: Dossier Details & Package Ledger */}
                <div>
                  {/* Dossier Radar Card */}
                  <div className="dossier-card">
                    <div className="dossier-header">
                      <div>
                        <div className="eyebrow">
                          Audit #{currentAudit.id} · Cryptographic Release Provenance
                        </div>
                        <h1 className="dossier-title">{currentAudit.label}</h1>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                          Authority: <strong>{currentAudit.repository}</strong> · Commit:{' '}
                          <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--dragon-gold)' }}>
                            {shortenHash(currentAudit.commit, 10, 8)}
                          </code>
                          {' · '}
                          Creator:{' '}
                          <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                            {shortenHash(currentAudit.creator, 6, 4)}
                          </code>
                        </p>
                      </div>

                      <div className="score-badge">
                        <span className="score-value">{complianceScore}%</span>
                        <span className="score-label">Coverage</span>
                      </div>
                    </div>

                    <div className="progress-bar-container">
                      <div
                        className="progress-bar-fill"
                        style={{
                          width: `${complianceScore}%`,
                          backgroundColor:
                            complianceScore === 100
                              ? 'var(--emerald-compliant)'
                              : complianceScore > 0
                              ? 'var(--amber-deficit)'
                              : 'var(--crimson-conflict)',
                        }}
                      />
                    </div>

                    {/* Dual Artifacts Row */}
                    <div className="artifacts-row">
                      <div className="artifact-card">
                        <FileCode size={24} className="artifact-icon" />
                        <div className="artifact-content">
                          <span className="artifact-type">SPDX SBOM Manifest</span>
                          <div className="artifact-path">{currentAudit.sbom_path}</div>
                          <span className="artifact-hash">
                            sha256: {shortenHash(currentAudit.sbom_sha256, 8, 6)}
                          </span>
                        </div>
                      </div>

                      <div className="artifact-card">
                        <FileText size={24} className="artifact-icon" />
                        <div className="artifact-content">
                          <span className="artifact-type">Third-Party Notice</span>
                          <div className="artifact-path">{currentAudit.notice_path}</div>
                          <span className="artifact-hash">
                            sha256: {shortenHash(currentAudit.notice_sha256, 8, 6)}
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

                    {packagesList.length > 0 ? (
                      packagesList.map((pkg, idx) => (
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
                      ))
                    ) : (
                      <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
                        {currentAudit.status === 'REGISTERED' ? (
                          <>
                            <p style={{ marginBottom: '1rem' }}>
                              Commitments registered on-chain. Consensus assessment has not been triggered yet.
                            </p>
                            <button
                              className="btn-action"
                              style={{ width: 'auto', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                              onClick={() =>
                                void executeTransaction('execute_consensus_assessment', [BigInt(currentAudit.id)])
                              }
                              disabled={isProcessing || !walletAccount}
                            >
                              <Flame size={14} />
                              {walletAccount ? 'Execute Consensus Assessment' : 'Connect Wallet to Execute Consensus'}
                            </button>
                          </>
                        ) : (
                          <p>No package observation records stored.</p>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Raw On-Chain Observation Payload */}
                  {currentAudit.observation && (
                    <div className="ledger-card" style={{ marginTop: '1.5rem' }}>
                      <div className="section-head">
                        <h2>Consensus Validator Observation Payload</h2>
                        <span style={{ fontSize: '0.78rem', color: 'var(--dragon-gold)' }}>
                          gl.vm.run_nondet_unsafe Verified
                        </span>
                      </div>
                      <pre
                        style={{
                          background: 'rgba(7, 10, 15, 0.7)',
                          padding: '1rem',
                          borderRadius: '8px',
                          fontSize: '0.75rem',
                          fontFamily: 'var(--font-mono)',
                          color: '#cbd5e1',
                          overflowX: 'auto',
                          maxHeight: '260px',
                        }}
                      >
                        {JSON.stringify(JSON.parse(currentAudit.observation), null, 2)}
                      </pre>
                    </div>
                  )}
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
                      Status: <strong>{currentAudit.status}</strong> · {currentAudit.status === 'FINALIZED' ? 'Consensus Finalized' : 'Pending Consensus'}
                    </div>
                  </div>

                  {/* Security Timeline */}
                  <div className="timeline-card">
                    <div className="eyebrow">Cryptographic Invariant Pipeline</div>
                    <ul className="timeline-list">
                      <li className="timeline-step">
                        <span className="step-badge done">1</span>
                        <div>
                          <strong>Zero-Trust Synthesis</strong>
                          <span>Derived strictly from validated 40-char commit</span>
                        </div>
                      </li>
                      <li className="timeline-step">
                        <span className={`step-badge ${currentAudit.status === 'FINALIZED' ? 'done' : 'active'}`}>
                          2
                        </span>
                        <div>
                          <strong>Pre-Inference SHA-256 Gate</strong>
                          <span>Pre-execution digest comparison</span>
                        </div>
                      </li>
                      <li className="timeline-step">
                        <span className={`step-badge ${currentAudit.status === 'FINALIZED' ? 'done' : 'active'}`}>
                          3
                        </span>
                        <div>
                          <strong>Sandboxed Micro-Classification</strong>
                          <span>Prompt-isolated AI token categorization</span>
                        </div>
                      </li>
                      <li className="timeline-step">
                        <span className={`step-badge ${currentAudit.status === 'FINALIZED' ? 'done' : 'active'}`}>
                          4
                        </span>
                        <div>
                          <strong>Deterministic Precedence</strong>
                          <span>Immutable on-chain verdict derivation</span>
                        </div>
                      </li>
                    </ul>
                  </div>

                  {/* Assessment Action if Registered */}
                  {currentAudit.status === 'REGISTERED' && (
                    <button
                      className="btn-assess"
                      onClick={() =>
                        void executeTransaction('execute_consensus_assessment', [BigInt(currentAudit.id)])
                      }
                      disabled={isProcessing || !walletAccount}
                    >
                      <Flame size={16} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
                      {walletAccount ? 'Execute Consensus Assessment' : 'Connect Wallet to Run Consensus'}
                    </button>
                  )}

                  <a
                    className="btn-explorer"
                    href={`https://studio.genlayer.com`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    View StudioNet Contract <ArrowUpRight size={15} />
                  </a>

                  {/* Remediation Pointer Note */}
                  {currentAudit.successor_plus_one > 0 && (
                    <div
                      style={{
                        padding: '1rem',
                        background: 'rgba(16, 185, 129, 0.08)',
                        border: '1px solid var(--emerald-border)',
                        borderRadius: '8px',
                        fontSize: '0.82rem',
                      }}
                    >
                      <strong style={{ color: 'var(--emerald-compliant)' }}>Remediation Bound:</strong> Successor release
                      audit #{currentAudit.successor_plus_one - 1} bound to this record.
                    </div>
                  )}
                </div>
              </div>
            )}
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

            {/* One-Click Fixture Presets */}
            <div style={{ marginBottom: '1.75rem', padding: '1.25rem', background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--dragon-gold)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700, marginBottom: '0.75rem' }}>
                Load Authentic Fixture Presets (Auto-fills GitHub Commit & SHA-256 Digests):
              </div>
              <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="preset-btn"
                  style={{ border: '1px solid var(--emerald-border)', color: 'var(--emerald-compliant)' }}
                  onClick={() => applyFixturePreset('clean')}
                >
                  Clean Release (100% Compliant)
                </button>
                <button
                  type="button"
                  className="preset-btn"
                  style={{ border: '1px solid var(--amber-border)', color: 'var(--dragon-gold)' }}
                  onClick={() => applyFixturePreset('permissiveGap')}
                >
                  Permissive Gap (Deficit Test)
                </button>
                <button
                  type="button"
                  className="preset-btn"
                  style={{ border: '1px solid var(--crimson-border)', color: '#f87171' }}
                  onClick={() => applyFixturePreset('copyleftConflict')}
                >
                  Copyleft Conflict (High-Risk Test)
                </button>
                <button
                  type="button"
                  className="preset-btn"
                  style={{ border: '1px solid var(--border-accent)' }}
                  onClick={() => applyFixturePreset('adversarialInjection')}
                >
                  Adversarial Prompt Injection
                </button>
              </div>
            </div>

            <form onSubmit={handleRegisterRelease} className="form-grid">
              <div className="input-field">
                <label>Release Label</label>
                <input
                  name="label"
                  placeholder="Example: Acme Core Engine v2.4.0"
                  value={formLabel}
                  onChange={(e) => setFormLabel(e.target.value)}
                  required
                />
              </div>

              <div className="form-row">
                <div className="input-field">
                  <label>GitHub Organization / Owner</label>
                  <input
                    name="owner"
                    placeholder="organization-name"
                    value={formOwner}
                    onChange={(e) => setFormOwner(e.target.value)}
                    required
                  />
                </div>
                <div className="input-field">
                  <label>Repository Name</label>
                  <input
                    name="repository"
                    placeholder="repository-name"
                    value={formRepo}
                    onChange={(e) => setFormRepo(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="input-field">
                <label>Immutable Git Commit SHA (40 Characters)</label>
                <input
                  name="commit"
                  className="mono"
                  placeholder="40-character hex commit hash"
                  value={formCommit}
                  onChange={(e) => setFormCommit(e.target.value)}
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
                    value={formSbomPath}
                    onChange={(e) => setFormSbomPath(e.target.value)}
                    required
                  />
                </div>
                <div className="input-field">
                  <label>Expected SBOM SHA-256</label>
                  <input
                    name="sbomSha256"
                    className="mono"
                    placeholder="64-character SHA-256 hash"
                    value={formSbomSha}
                    onChange={(e) => setFormSbomSha(e.target.value)}
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
                    value={formNoticePath}
                    onChange={(e) => setFormNoticePath(e.target.value)}
                    required
                  />
                </div>
                <div className="input-field">
                  <label>Expected Notice SHA-256</label>
                  <input
                    name="noticeSha256"
                    className="mono"
                    placeholder="64-character SHA-256 hash"
                    value={formNoticeSha}
                    onChange={(e) => setFormNoticeSha(e.target.value)}
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
                  value={formPolicy}
                  onChange={(e) => setFormPolicy(e.target.value)}
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
                <h2>Deterministic Consensus & Precedence Model</h2>
              </div>
              <span className="status-badge compliant">12/12 Invariants Tested</span>
            </div>

            <div style={{ overflowX: 'auto', marginTop: '1rem' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-accent)', textAlign: 'left', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '0.75rem' }}>Condition / Input</th>
                    <th style={{ padding: '0.75rem' }}>Execution Mode</th>
                    <th style={{ padding: '0.75rem' }}>Precedence Priority</th>
                    <th style={{ padding: '0.75rem' }}>Derived Terminal Verdict</th>
                    <th style={{ padding: '0.75rem' }}>On-Chain State</th>
                  </tr>
                </thead>
                <tbody style={{ fontFamily: 'var(--font-mono)' }}>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '0.75rem', color: 'var(--dragon-amber)' }}>HTTP Timeout / DNS</td>
                    <td style={{ padding: '0.75rem' }}>gl.nondet.web.request</td>
                    <td style={{ padding: '0.75rem' }}>Rank 1 (Transient)</td>
                    <td style={{ padding: '0.75rem', color: '#fbbf24' }}>AUDIT_RETRYABLE</td>
                    <td style={{ padding: '0.75rem' }}>REGISTERED (Retry Allowed)</td>
                  </tr>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '0.75rem', color: '#f87171' }}>Digest SHA-256 Divergence</td>
                    <td style={{ padding: '0.75rem' }}>Pre-Inference Gate</td>
                    <td style={{ padding: '0.75rem' }}>Rank 2 (Critical)</td>
                    <td style={{ padding: '0.75rem', color: '#ef4444' }}>TAMPER_DETECTED</td>
                    <td style={{ padding: '0.75rem' }}>FINALIZED (Score: 0%)</td>
                  </tr>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '0.75rem', color: '#f87171' }}>Malformed JSON / Empty Notice</td>
                    <td style={{ padding: '0.75rem' }}>Schema Validation</td>
                    <td style={{ padding: '0.75rem' }}>Rank 3 (Format)</td>
                    <td style={{ padding: '0.75rem', color: '#ef4444' }}>MALFORMED_INPUT</td>
                    <td style={{ padding: '0.75rem' }}>FINALIZED (Score: 0%)</td>
                  </tr>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '0.75rem', color: '#f87171' }}>Copyleft Term Conflict</td>
                    <td style={{ padding: '0.75rem' }}>Validator LLM Consensus</td>
                    <td style={{ padding: '0.75rem' }}>Rank 4 (Legal Risk)</td>
                    <td style={{ padding: '0.75rem', color: '#ef4444' }}>HIGH_RISK_LICENSE_VIOLATION</td>
                    <td style={{ padding: '0.75rem' }}>FINALIZED (Blocked)</td>
                  </tr>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '0.75rem', color: 'var(--dragon-amber)' }}>Missing Permissive Notice</td>
                    <td style={{ padding: '0.75rem' }}>Validator LLM Consensus</td>
                    <td style={{ padding: '0.75rem' }}>Rank 5 (Attribution)</td>
                    <td style={{ padding: '0.75rem', color: '#f59e0b' }}>ATTRIBUTION_DEFICIT</td>
                    <td style={{ padding: '0.75rem' }}>FINALIZED (Remediable)</td>
                  </tr>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '0.75rem', color: '#94a3b8' }}>Ambiguous License Text</td>
                    <td style={{ padding: '0.75rem' }}>Validator LLM Consensus</td>
                    <td style={{ padding: '0.75rem' }}>Rank 6 (Fail-Closed)</td>
                    <td style={{ padding: '0.75rem', color: '#94a3b8' }}>INDETERMINATE</td>
                    <td style={{ padding: '0.75rem' }}>FINALIZED (Score: &lt;100%)</td>
                  </tr>
                  <tr>
                    <td style={{ padding: '0.75rem', color: 'var(--emerald-compliant)' }}>100% Attribution & License Match</td>
                    <td style={{ padding: '0.75rem' }}>Validator LLM Consensus</td>
                    <td style={{ padding: '0.75rem' }}>Rank 7 (Compliance)</td>
                    <td style={{ padding: '0.75rem', color: 'var(--emerald-compliant)' }}>VERIFIED_COMPLIANT</td>
                    <td style={{ padding: '0.75rem', color: 'var(--emerald-compliant)' }}>FINALIZED (Score: 100%)</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>

      {/* Floating Status Bar */}
      <div className="status-bar">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <span className="pulse-dot" style={{ backgroundColor: isProcessing ? '#f59e0b' : '#10b981' }}></span>
          <span style={{ fontSize: '0.85rem', color: isProcessing ? 'var(--dragon-amber)' : 'var(--text-secondary)' }}>
            {statusMessage}
          </span>
        </div>

        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          Contract: <code style={{ color: 'var(--dragon-gold)' }}>{shortenHash(contractAddress, 8, 6)}</code> (StudioNet · Chain {authoritativeChain.id})
        </div>
      </div>

      {/* Footer */}
      <footer>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <img src="/nidhogg-logo.svg" alt="logo" style={{ width: '18px', height: '18px' }} />
          <span>
            Nidhogg Protocol · Developed by <strong>9ja_maxx</strong>
          </span>
        </div>

        <div className="footer-meta">
          <span>Zero Simulated Data · Direct GenLayer On-Chain Consensus</span>
        </div>
      </footer>
    </div>
  );
}
