import { ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import type { ActiveTunnel, Audit, MutationResult, PageData, Pagination as PaginationData, SecurityMetric } from './types';
import { formatLocalDate, securityEventDescription, securityEventLabel } from './utils';

type Mutate = (path: string, data?: FormData) => Promise<boolean>;

function LocalTime({ value }: { value: string }) {
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return <time dateTime={value} title={`${zone} の時刻`}>{formatLocalDate(value)}</time>;
}
function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: string }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
function CopyButton({ value, small = false }: { value: string; small?: boolean }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };
  return <button type="button" className={`copy${small ? ' small' : ''}`} onClick={() => void copy()}>{copied ? 'コピー済み' : 'コピー'}</button>;
}
function Empty({ icon, title, text, children }: { icon?: string; title: string; text?: string; children?: ReactNode }) {
  return <div className="empty">{icon && <span>{icon}</span>}<h3>{title}</h3>{text && <p>{text}</p>}{children}</div>;
}
export function Modal({ open, onClose, title, eyebrow, children, onSubmit, submitLabel }: { open: boolean; onClose: () => void; title: string; eyebrow: string; children: ReactNode; onSubmit: (form: FormData) => Promise<boolean>; submitLabel: string }) {
  const ref = useRef<HTMLDialogElement>(null);
  const submittingRef = useRef(false);
  const [submitting, setSubmitting] = useState(false);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);
  return <dialog ref={ref} onClose={onClose} onCancel={(event) => { if (submitting) event.preventDefault(); }} aria-labelledby="modal-title" aria-busy={submitting}>
    <form onSubmit={(event) => {
      event.preventDefault();
      if (submittingRef.current) return;
      submittingRef.current = true;
      setSubmitting(true);
      void onSubmit(new FormData(event.currentTarget)).then((ok) => { if (ok) onClose(); }).finally(() => {
        submittingRef.current = false;
        setSubmitting(false);
      });
    }}>
      <div className="modal-head"><div><p className="eyebrow">{eyebrow}</p><h2 id="modal-title">{title}</h2></div><button type="button" className="icon-button" onClick={onClose} aria-label="閉じる" disabled={submitting}>×</button></div>
      {children}
      <div className="modal-actions"><button type="button" className="button ghost" onClick={onClose} disabled={submitting}>キャンセル</button><button className="button" disabled={submitting}>{submitting ? '送信中…' : submitLabel}</button></div>
    </form>
  </dialog>;
}
function ConfirmButton({ message, className = 'link-button danger', children, action, mutate }: { message: string; className?: string; children: ReactNode; action: string; mutate: Mutate }) {
  return <button type="button" className={className} onClick={() => { if (window.confirm(message)) void mutate(action); }}>{children}</button>;
}
function Pagination({ value }: { value?: PaginationData }) {
  const navigate = useNavigate();
  if (!value?.Page) return null;
  return <nav className="pagination" aria-label="ページネーション">
    <div>{value.PreviousURL && <Link className="button secondary" to={value.PreviousURL} rel="prev">← 前へ</Link>}</div>
    <span>{value.Page}ページ</span>
    <div className="pagination-end">{value.NextURL && <Link className="button secondary" to={value.NextURL} rel="next">次へ →</Link>}</div>
    <label className="page-size">表示件数<select value={(value.PageSizes ?? []).find((item) => item.Selected)?.URL ?? ''} onChange={(event) => navigate(event.target.value)}>{(value.PageSizes ?? []).map((item) => <option key={item.Size} value={item.URL}>{item.Size}件</option>)}</select></label>
  </nav>;
}
function PageHead({ eyebrow, title, text, action }: { eyebrow?: string; title: string; text: string; action?: ReactNode }) {
  return <div className="page-head"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1><p className="muted">{text}</p></div>{action}</div>;
}

function Login() {
  useEffect(() => { document.title = 'Sign in · Tunnel'; }, []);
  return <main className="login-shell"><section className="login-card">
    <img className="login-logo" src="/static/logo.svg" alt="Tunnel" />
    <p className="eyebrow">セルフホスト型トンネル</p><h1>ローカルサービスを<br />安全に公開。</h1>
    <p className="muted">SSH reverse forwardingを、安全な鍵認証と予約済みサブドメインで管理します。</p>
    <a className="button discord full" href="/auth/discord"><span aria-hidden="true">◈</span> Discordでログイン</a>
    <p className="fine">ログインすることでサービスのセキュリティポリシーに同意したものとみなします。</p>
  </section></main>;
}

const userNav = [['/', '概要'], ['/keys', 'SSH公開鍵'], ['/subdomains', 'サブドメイン'], ['/tcp-ports', 'TCPポート'], ['/tunnels', '接続中のトンネル']];
const adminNav = [['/admin', '管理概要'], ['/admin/users', 'ユーザー'], ['/admin/keys', '全SSH公開鍵'], ['/admin/subdomains', '全サブドメイン'], ['/admin/tcp-ports', '全TCPポート'], ['/admin/tunnels', '接続中のトンネル'], ['/admin/security', 'セキュリティ検知']];
function Sidebar({ data, open, close, mutate }: { data: PageData; open: boolean; close: () => void; mutate: Mutate }) {
  const navClass = ({ isActive }: { isActive: boolean }) => isActive ? 'active' : '';
  return <aside className={`sidebar${open ? ' open' : ''}`} id="sidebar">
    <Link className="logo" to="/" onClick={close}><img src="/static/logo.svg" alt="Tunnel" /></Link>
    <nav><p className="nav-label">ワークスペース</p>{userNav.map(([to, label]) => <NavLink key={to} to={to} end onClick={close} className={navClass}>{label}</NavLink>)}
      {data.User.Role === 'admin' && <><p className="nav-label admin-label">管理</p>{adminNav.map(([to, label]) => <NavLink key={to} to={to} end onClick={close} className={navClass}>{label}</NavLink>)}</>}
    </nav>
    <div className="sidebar-user">{data.User.AvatarURL ? <img src={data.User.AvatarURL} alt="" /> : <span className="avatar">{Array.from(data.User.Username)[0] ?? '?'}</span>}<div><strong>{data.User.DisplayName}</strong><small>{data.User.Role}</small></div><button className="icon-button" title="ログアウト" aria-label="ログアウト" onClick={() => void mutate('/logout')}>↪</button></div>
  </aside>;
}

function Metric({ label, value, detail }: { label: string; value: ReactNode; detail: string }) { return <article className="card metric"><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>; }
function Activity({ values, admin = false }: { values?: Audit[]; admin?: boolean }) {
  return values?.length ? <div className="activity">{values.map((item, i) => <div key={`${item.CreatedAt}-${i}`}><span className="activity-dot" /><p><strong>{item.Action}</strong><small>{admin && `${item.SourceIP} · `}<LocalTime value={item.CreatedAt} /></small></p></div>)}</div> : <Empty icon={admin ? undefined : '◎'} title={admin ? 'イベントはありません' : '操作履歴はありません'} text={admin ? undefined : '操作履歴がここに表示されます。'} />;
}
function Status({ available, normal = '同期済み' }: { available?: boolean; normal?: string }) { return <span className="status">{available ? <><i /> {normal}</> : '取得不可 / 情報が古い'}</span>; }

function Dashboard({ p }: { p: PageData }) {
  const tcpCommand = p.TCPConnectCommand ?? '';
  return <><PageHead eyebrow="ワークスペース概要" title={`${p.User.DisplayName} さん`} text="トンネルサービスの設定と接続状況。" action={<Status available normal="サービス稼働中" />} />
    <div className="metrics"><Metric label="SSH公開鍵" value={p.KeyCount ?? 0} detail="件の登録" /><Metric label="サブドメイン" value={p.SubdomainCount ?? 0} detail="件の予約" /><Metric label="TCPポート" value={p.TCPPortCount ?? 0} detail="件の予約" /><Metric label="接続中のトンネル" value={p.ActiveTunnelAvailable ? (p.ActiveTunnelCount ?? 0) : '—'} detail={p.ActiveTunnelAvailable ? '同期済み sish state' : '取得不可 / 情報が古い'} /></div>
    <section className="card guide-card"><div className="card-head"><p className="eyebrow">はじめに</p><h2>トンネルを公開する手順</h2><p className="muted">ローカルで動くWebサービスを、登録したSSH公開鍵と予約済みサブドメインで安全に公開します。</p></div><ol className="steps">
      <li><span>1</span><div><h3>SSH公開鍵を登録</h3><p>「SSH公開鍵」で端末の公開鍵（例: <code>~/.ssh/id_ed25519.pub</code>）を追加します。秘密鍵は登録しません。</p></div></li>
      <li><span>2</span><div><h3>サブドメインを予約</h3><p>公開URLに使う名前を予約します。コマンドには最初の予約名が自動で入ります。</p></div></li>
      <li><span>3</span><div><h3>ローカルサービスを起動して接続</h3><p>例では <code>localhost:3000</code> を公開します。別ポートの場合は末尾を変更してください。</p><div className="code-row"><code>{p.ConnectCommand}</code><CopyButton value={p.ConnectCommand ?? ''} /></div></div></li>
      <li><span>4</span><div><h3>公開を確認</h3><p>「接続中のトンネル」に表示されたら、予約したURLを開きます。SSHを終了すると公開も終了します。</p></div></li>
    </ol><div className="notice">接続できない場合は、登録鍵が有効か、予約名と <code>-R</code> の名前が一致するか、ローカルサービスが起動中かを確認してください。</div></section>
    <section className="card guide-card"><div className="card-head"><p className="eyebrow">TCPトンネル</p><h2>MinecraftなどのTCPサービスを公開する手順</h2><p className="muted">TCP専用範囲10000〜65535のポートを予約してから、同じ公開ポートをSSH reverse forwardingで指定します。</p></div><ol className="steps">
      <li><span>1</span><div><h3>TCPポートを予約</h3><p>「TCPポート」で未使用のポートを予約します。Minecraft Java Editionの既定ポートは <code>25565</code> です。</p></div></li><li><span>2</span><div><h3>ローカルサービスを起動</h3><p>Minecraftサーバーなどがローカルで待受していることを確認します。</p></div></li>
      <li><span>3</span><div><h3>TCPトンネルへ接続</h3><p>{p.FirstTCPPort ? <>予約済みポート <code>{p.FirstTCPPort}</code> の例です。<code>LOCAL_PORT</code>をローカルサービスのポートへ置き換えてください。</> : <>先に「TCPポート」でポートを予約し、<code>PUBLIC_PORT</code>を予約した公開ポート、<code>LOCAL_PORT</code>をローカルサービスのポートへ置き換えてください。</>}</p><div className="code-row"><code>{tcpCommand}</code><CopyButton value={tcpCommand} /></div></div></li>
      <li><span>4</span><div><h3>外部から接続</h3><p>接続先は <code>{p.SSHHost}:予約ポート</code> です。<code>{p.SSHHost}</code> はこの環境のSSH接続ホストで、コード固定値ではありません。</p></div></li>
    </ol><div className="notice">未予約または他ユーザー所有のポートは拒否されます。Minecraft Bedrock EditionなどUDPを必要とするサービスには対応していません。</div></section>
    <div className="split"><section className="card"><div className="card-head"><h2>最近の操作</h2></div><Activity values={p.Audit} /></section><section className="card"><div className="card-head"><h2>接続先情報</h2></div><dl className="details"><div><dt>SSHホスト</dt><dd><code>{p.SSHHost}</code></dd></div><div><dt>SSHポート</dt><dd><code>{p.SSHPort}</code></dd></div><div><dt>トンネルドメイン</dt><dd><code>*.{p.TunnelDomain}</code></dd></div><div><dt>認証</dt><dd><Badge tone="green">公開鍵</Badge></dd></div></dl></section></div>
  </>;
}

function Keys({ p, mutate }: { p: PageData; mutate: Mutate }) {
  const [open, setOpen] = useState(false), keys = p.Keys ?? [];
  return <><PageHead eyebrow="アクセス管理" title="SSH公開鍵" text="sishゲートウェイへの接続を許可する公開鍵。秘密鍵は入力しないでください。" action={<button className="button" onClick={() => setOpen(true)}>＋ SSH公開鍵を追加</button>} />
    <section className="card table-card">{keys.length ? <div className="table-wrap"><table><thead><tr><th>名前</th><th>フィンガープリント</th><th>状態</th><th>作成日時</th><th /></tr></thead><tbody>{keys.map((key) => <tr key={key.ID}><td><strong>{key.Name}</strong><small className="key-preview">{key.PublicKey}</small></td><td><code>{key.Fingerprint}</code></td><td><Badge tone={key.Enabled ? 'green' : 'gray'}>{key.Enabled ? '有効' : '無効'}</Badge></td><td><LocalTime value={key.CreatedAt} /></td><td className="actions"><button className="link-button" onClick={() => void mutate(`/keys/${key.ID}/${key.Enabled ? 'disable' : 'enable'}`)}>{key.Enabled ? 'Disable' : 'Enable'}</button><ConfirmButton message="このSSH公開鍵を削除しますか？" action={`/keys/${key.ID}/delete`} mutate={mutate}>削除</ConfirmButton></td></tr>)}</tbody></table></div> : <Empty icon="⌁" title="SSH公開鍵はありません" text="最初の公開鍵を追加してゲートウェイへ接続しましょう。"><button className="button secondary" onClick={() => setOpen(true)}>SSH公開鍵を追加</button></Empty>}</section>
    <Modal open={open} onClose={() => setOpen(false)} eyebrow="新しい認証情報" title="SSH公開鍵を追加" submitLabel="追加" onSubmit={(form) => mutate('/keys', form)}><label>名前<input name="name" maxLength={80} required placeholder="Work laptop" /></label><label>OpenSSH公開鍵<textarea name="public_key" maxLength={16384} rows={6} required placeholder="ssh-ed25519 AAAA… user@device" /></label><p className="fine">公開鍵のみ保存します。秘密鍵（BEGIN OPENSSH PRIVATE KEY）は絶対に貼り付けないでください。</p></Modal>
  </>;
}

function Subdomains({ p, mutate }: { p: PageData; mutate: Mutate }) {
  const [open, setOpen] = useState(false), domains = p.Subdomains ?? [];
  return <><PageHead eyebrow="公開先設定" title="サブドメイン" text="トンネル用ホスト名を予約します。Vercel DNSの明示レコードと安全に競合確認します。" action={<button className="button" onClick={() => setOpen(true)}>＋ サブドメインを予約</button>} />
    <section className="card table-card">{domains.length ? <div className="table-wrap"><table><thead><tr><th>ホスト名</th><th>状態</th><th>公開URL</th><th>作成日時</th><th /></tr></thead><tbody>{domains.map((domain) => { const url = `https://${domain.Name}.${p.TunnelDomain}`; return <tr key={domain.ID}><td><strong>{domain.Name}.{p.TunnelDomain}</strong></td><td><Badge tone="green">予約済み</Badge></td><td><div className="inline-copy"><code>{url}</code><CopyButton value={url} small /></div></td><td><LocalTime value={domain.CreatedAt} /></td><td><ConfirmButton message="このサブドメイン予約を解放しますか？" action={`/subdomains/${domain.ID}/release`} mutate={mutate}>解放</ConfirmButton></td></tr>; })}</tbody></table></div> : <Empty icon="◇" title="予約済みサブドメインはありません" text="公開するサービス用の名前を予約してください。"><button className="button secondary" onClick={() => setOpen(true)}>サブドメインを予約</button></Empty>}</section>
    <Modal open={open} onClose={() => setOpen(false)} eyebrow="新しい公開先" title="サブドメインを予約" submitLabel="予約" onSubmit={(form) => mutate('/subdomains', form)}><label>サブドメイン<div className="input-suffix"><input name="name" maxLength={63} pattern="[A-Za-z0-9-]+" required placeholder="myapp" /><span>.{p.TunnelDomain}</span></div></label><p className="fine">予約前に既存DBとVercel DNSを確認します。DNS API障害時は安全のため予約を拒否します。</p></Modal>
  </>;
}

function TCPPorts({ p, mutate }: { p: PageData; mutate: Mutate }) {
  const [open, setOpen] = useState(false), ports = p.TCPPorts ?? [];
  return <><PageHead eyebrow="公開先設定" title="TCPポート" text="TCPトンネルでbindするポートを事前に予約します。" action={<button className="button" onClick={() => setOpen(true)}>＋ TCPポートを予約</button>} />
    <section className="card table-card">{ports.length ? <div className="table-wrap"><table><thead><tr><th>ポート</th><th>状態</th><th>接続例</th><th>作成日時</th><th /></tr></thead><tbody>{ports.map((port) => <tr key={port.ID}><td><strong>:{port.Port}</strong></td><td><Badge tone="green">予約済み</Badge></td><td><code>ssh -p {p.SSHPort} -R {port.Port}:localhost:LOCAL_PORT {p.SSHHost}</code></td><td><LocalTime value={port.CreatedAt} /></td><td><ConfirmButton message="このTCPポート予約を解放しますか？ 接続中のトンネルは切断されます。" action={`/tcp-ports/${port.ID}/release`} mutate={mutate}>解放</ConfirmButton></td></tr>)}</tbody></table></div> : <Empty title="予約済みTCPポートはありません" text="TCPトンネルを利用する前にポートを予約してください。"><button className="button secondary" onClick={() => setOpen(true)}>TCPポートを予約</button></Empty>}</section>
    <Modal open={open} onClose={() => setOpen(false)} eyebrow="新しい公開先" title="TCPポートを予約" submitLabel="予約" onSubmit={(form) => mutate('/tcp-ports', form)}><label>TCPポート<input name="port" type="number" min={10000} max={65535} step={1} required placeholder="25565" /></label><p className="fine">TCPトンネル専用範囲の10000〜65535を予約できます。OS上のbind可否や競合は接続時に判定されます。</p></Modal>
  </>;
}

function TunnelTable({ tunnels, admin = false }: { tunnels: ActiveTunnel[]; admin?: boolean }) {
  if (!tunnels.length) return <Empty title="接続中のトンネルはありません" text={admin ? undefined : '現在接続中のトンネルはありません。'} />;
  return <div className="table-wrap"><table><thead><tr>{admin && <th>所有者</th>}<th>プロトコル</th><th>公開先</th><th>SSH公開鍵</th><th>{admin ? '接続元' : '接続元IP'}</th><th>状態</th><th>接続日時</th></tr></thead><tbody>{tunnels.map((tunnel, index) => <tr key={`${tunnel.protocol}-${tunnel.hostname}-${tunnel.port}-${tunnel.source_ip}-${tunnel.connected_at}-${index}`}>{admin && <td>{tunnel.owner}</td>}<td><Badge>{tunnel.protocol}</Badge></td><td><strong>{tunnel.hostname || `TCP :${tunnel.port}`}</strong></td><td>{tunnel.key_name}</td><td><code>{tunnel.source_ip}</code></td><td><Badge tone={tunnel.status === 'active' ? 'green' : 'gray'}>{tunnel.status}</Badge></td><td><LocalTime value={tunnel.connected_at} /></td></tr>)}</tbody></table></div>;
}
function Tunnels({ p }: { p: PageData }) { return <><PageHead eyebrow="接続状況" title="接続中のトンネル" text="sishが報告した実際の接続のみを表示します。" action={<Status available={p.ActiveTunnelAvailable} />} /><section className="card table-card"><TunnelTable tunnels={p.ActiveTunnels ?? []} /></section></>; }

function AdminHome({ p }: { p: PageData }) { const s = p.Stats; if (!s) return null; return <><PageHead eyebrow="管理" title="システム概要" text="ユーザー、認証鍵、予約状況とセキュリティイベント。" action={<Status available normal="管理機能 稼働中" />} /><div className="metrics admin-metrics"><Metric label="ユーザー" value={s.Users} detail={`${s.ActiveUsers} active`} /><Metric label="SSH公開鍵" value={s.SSHKeys} detail="登録済み" /><Metric label="サブドメイン" value={s.Subdomains} detail="予約済み" /><Metric label="TCPポート" value={s.TCPPorts} detail="予約済み" /><Metric label="停止中" value={s.SuspendedUsers} detail="ユーザー" /><Metric label="接続中のトンネル" value={s.ActiveTunnels} detail="sish接続中" /></div><section className="card padded-card"><div className="card-head"><h2>最近のセキュリティ・管理イベント</h2></div><Activity values={p.Audit} admin /></section></>; }
function AdminUsers({ p, mutate }: { p: PageData; mutate: Mutate }) { return <><PageHead eyebrow="管理" title="ユーザー" text="停止するとセッションを破棄し、登録鍵をsish認証対象から除外します。" /><section className="card table-card"><div className="table-wrap"><table><thead><tr><th>ユーザー</th><th>Discord ID / Email</th><th>権限</th><th>状態</th><th>鍵 / サブドメイン / TCPポート</th><th>作成日時</th><th /></tr></thead><tbody>{(p.Users ?? []).map((user) => <tr key={user.ID}><td><div className="user-cell">{user.AvatarURL && <img src={user.AvatarURL} alt="" />}<strong>{user.Username}</strong></div></td><td><code>{user.DiscordID}</code><small>{user.Email}</small></td><td><Badge>{user.Role}</Badge></td><td><Badge tone={user.Status === 'active' ? 'green' : 'red'}>{user.Status === 'active' ? '有効' : '停止中'}</Badge></td><td>{user.SSHKeyCount} / {user.SubdomainCount} / {user.TCPPortCount}</td><td><LocalTime value={user.CreatedAt} /></td><td>{user.Role === 'user' && <ConfirmButton message="ユーザー状態を変更しますか？" className={`link-button${user.Status === 'active' ? ' danger' : ''}`} action={`/admin/users/${user.ID}/${user.Status === 'active' ? 'suspend' : 'unsuspend'}`} mutate={mutate}>{user.Status === 'active' ? 'Suspend' : 'Unsuspend'}</ConfirmButton>}</td></tr>)}</tbody></table></div><Pagination value={p.Pagination} /></section></>; }
function AdminKeys({ p, mutate }: { p: PageData; mutate: Mutate }) { return <><PageHead eyebrow="管理" title="全SSH公開鍵" text="全ユーザーの認証鍵を確認・無効化・削除します。" /><section className="card table-card"><div className="table-wrap"><table><thead><tr><th>所有者</th><th>名前</th><th>フィンガープリント</th><th>状態</th><th>作成日時</th><th /></tr></thead><tbody>{(p.Keys ?? []).map((key) => <tr key={key.ID}><td><strong>{key.Owner}</strong></td><td>{key.Name}</td><td><code>{key.Fingerprint}</code></td><td><Badge tone={key.Enabled ? 'green' : 'gray'}>{key.Enabled ? '有効' : '無効'}</Badge></td><td><LocalTime value={key.CreatedAt} /></td><td className="actions"><button className="link-button" onClick={() => void mutate(`/admin/keys/${key.ID}/${key.Enabled ? 'disable' : 'enable'}`)}>{key.Enabled ? 'Disable' : 'Enable'}</button><ConfirmButton message="この鍵を完全にrevokeしますか？" action={`/admin/keys/${key.ID}/revoke`} mutate={mutate}>削除</ConfirmButton></td></tr>)}</tbody></table></div><Pagination value={p.Pagination} /></section></>; }
function AdminSubdomains({ p, mutate }: { p: PageData; mutate: Mutate }) { return <><PageHead eyebrow="管理" title="全サブドメイン" text="予約台帳です。予約時にDNS競合を安全側に倒して検査しています。" /><section className="card table-card"><div className="table-wrap"><table><thead><tr><th>ホスト名</th><th>所有者</th><th>状態</th><th>DNS競合</th><th>作成日時</th><th /></tr></thead><tbody>{(p.Subdomains ?? []).map((domain) => <tr key={domain.ID}><td><strong>{domain.Name}.{p.TunnelDomain}</strong></td><td>{domain.Owner}</td><td><Badge tone="green">予約済み</Badge></td><td><Badge tone={domain.DNSConflict === 'Conflict' ? 'red' : domain.DNSConflict === 'None' ? 'green' : 'gray'}>{domain.DNSConflict === 'Conflict' ? '競合あり' : domain.DNSConflict === 'None' ? 'なし' : '取得不可'}</Badge></td><td><LocalTime value={domain.CreatedAt} /></td><td><ConfirmButton message="この予約を強制解放しますか？" action={`/admin/subdomains/${domain.ID}/release`} mutate={mutate}>強制解放</ConfirmButton></td></tr>)}</tbody></table></div><Pagination value={p.Pagination} /></section></>; }
function AdminTCPPorts({ p, mutate }: { p: PageData; mutate: Mutate }) { return <><PageHead eyebrow="管理" title="全TCPポート" text="TCPポート予約台帳です。強制解放すると接続中の該当トンネルを切断します。" /><section className="card table-card"><div className="table-wrap"><table><thead><tr><th>ポート</th><th>所有者</th><th>状態</th><th>作成日時</th><th /></tr></thead><tbody>{(p.TCPPorts ?? []).map((port) => <tr key={port.ID}><td><strong>:{port.Port}</strong></td><td>{port.Owner}</td><td><Badge tone="green">予約済み</Badge></td><td><LocalTime value={port.CreatedAt} /></td><td><ConfirmButton message="このTCPポート予約を強制解放しますか？" action={`/admin/tcp-ports/${port.ID}/release`} mutate={mutate}>強制解放</ConfirmButton></td></tr>)}</tbody></table></div><Pagination value={p.Pagination} /></section></>; }
function SecurityTable({ values }: { values: SecurityMetric[] }) { return values.length ? <div className="table-wrap"><table><thead><tr><th>検知時刻</th><th>検知内容</th><th>システムの対応</th><th className="count">件数</th></tr></thead><tbody>{values.map((metric, i) => <tr key={`${metric.BucketStart}-${metric.EventType}-${i}`}><td><LocalTime value={metric.BucketStart} /></td><td><strong>{securityEventLabel(metric.EventType)}</strong><small><code>{metric.EventType}</code></small></td><td>{securityEventDescription(metric.EventType)}</td><td className="count"><strong>{metric.Count}</strong></td></tr>)}</tbody></table></div> : <Empty title="セキュリティ検知はありません" text="拒否・制限した通信がここに表示されます。" />; }
function AdminTunnels({ p }: { p: PageData }) { return <><PageHead eyebrow="管理" title="接続中のトンネル" text="sishが報告した全ユーザーの接続状況です。" action={<Status available={p.ActiveTunnelAvailable} />} /><section className="card table-card"><TunnelTable tunnels={p.ActiveTunnels ?? []} admin /><Pagination value={p.Pagination} /></section></>; }
function AdminSecurity({ p }: { p: PageData }) { return <><PageHead eyebrow="管理" title="セキュリティ検知" text="拒否・制限した通信と、システムが実行した対応を1分単位で表示します。" /><section className="card table-card"><SecurityTable values={p.SecurityMetrics ?? []} /><Pagination value={p.Pagination} /></section></>; }

function CurrentPage({ data, mutate }: { data: PageData; mutate: Mutate }) {
  switch (data.Page) {
    case 'dashboard': return <Dashboard p={data} />;
    case 'keys': return <Keys p={data} mutate={mutate} />;
    case 'subdomains': return <Subdomains p={data} mutate={mutate} />;
    case 'tcp-ports': return <TCPPorts p={data} mutate={mutate} />;
    case 'tunnels': return <Tunnels p={data} />;
    case 'admin-home': return <AdminHome p={data} />;
    case 'admin-users': return <AdminUsers p={data} mutate={mutate} />;
    case 'admin-keys': return <AdminKeys p={data} mutate={mutate} />;
    case 'admin-subdomains': return <AdminSubdomains p={data} mutate={mutate} />;
    case 'admin-tcp-ports': return <AdminTCPPorts p={data} mutate={mutate} />;
    case 'admin-tunnels': return <AdminTunnels p={data} />;
    case 'admin-security': return <AdminSecurity p={data} />;
    default: return <Empty title="ページが見つかりません" />;
  }
}

export default function App() {
  const location = useLocation(), navigate = useNavigate();
  const [data, setData] = useState<PageData | null>(null), [error, setError] = useState(''), [toast, setToast] = useState<MutationResult | null>(null), [reload, setReload] = useState(0), [menu, setMenu] = useState(false);
  const isLogin = location.pathname === '/login';
  useEffect(() => { setToast(null); }, [location.pathname, location.search]);
  useEffect(() => {
    if (isLogin) return;
    const controller = new AbortController();
    setError(''); setMenu(false);
    fetch(`/api/page?path=${encodeURIComponent(location.pathname + location.search)}`, { credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: controller.signal })
      .then(async (response) => {
        if (response.redirected || response.status === 401) { window.location.assign('/login'); return null; }
        if (!response.ok) throw new Error(response.status === 403 ? 'この画面を表示する権限がありません' : '画面を読み込めませんでした');
        if (!response.headers.get('content-type')?.includes('application/json')) { window.location.assign('/login'); return null; }
        return response.json() as Promise<PageData>;
      }).then((page) => { if (page) { setData(page); document.title = `${page.Title} · Tunnel`; } }).catch((reason: unknown) => { if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : '画面を読み込めませんでした'); });
    return () => controller.abort();
  }, [isLogin, location.pathname, location.search, reload]);

  const mutate = useCallback<Mutate>(async (path, form) => {
    if (!data) return false;
    const body = new URLSearchParams();
    body.set('csrf_token', data.CSRF);
    body.set('_action', path);
    form?.forEach((value, key) => { if (typeof value === 'string') body.set(key, value); });
    let response: Response;
    try {
      response = await fetch('/api/action', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    } catch {
      setToast({ flash: '', error: '通信に失敗しました。もう一度お試しください' });
      return false;
    }
    if (response.redirected) { window.location.assign('/login'); return false; }
    if (path === '/logout' && response.ok) { navigate('/login'); setData(null); return true; }
    let result: MutationResult;
    try { result = await response.json() as MutationResult; } catch { result = { flash: '', error: response.status === 403 ? 'CSRF validation failed' : '操作を完了できませんでした' }; }
    setToast(result);
    if (response.ok) setReload((value) => value + 1);
    return response.ok;
  }, [data, navigate]);

  if (isLogin) return <Login />;
  if (!data) return <main className="grid min-h-screen place-items-center bg-[#1e1f22] text-[#b5bac1]" aria-live="polite">{error || '読み込み中…'}</main>;
  return <div className="shell"><Sidebar data={data} open={menu} close={() => setMenu(false)} mutate={mutate} /><div className="content"><header className="mobile-header"><Link className="logo" to="/"><img src="/static/logo.svg" alt="Tunnel" /></Link><button className="icon-button" aria-label="メニュー" aria-controls="sidebar" aria-expanded={menu} onClick={() => setMenu((value) => !value)}>☰</button></header><main>
    {(toast?.flash || data.Flash) && <div className="toast success" role="status"><span>✓</span>{toast?.flash || data.Flash}</div>}
    {(toast?.error || data.Error || error) && <div className="toast error" role="alert"><span>!</span>{toast?.error || data.Error || error}</div>}
    <CurrentPage data={data} mutate={mutate} />
  </main></div></div>;
}
