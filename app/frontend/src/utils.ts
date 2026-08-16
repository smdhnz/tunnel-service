export function formatLocalDate(value: string, timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone): string {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) return '-';
  return new Intl.DateTimeFormat('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false, timeZone,
  }).format(date);
}

export function securityEventLabel(event: string): string {
  return ({
    unknown_host: '未登録ホストへのアクセス',
    rate_limited: 'アクセス頻度の上限超過',
    temporarily_blocked: '一時的にブロック',
    connection_limited: '同時接続数の上限超過',
    authorization_denied: '認証・認可の拒否',
  } as Record<string, string>)[event] ?? event;
}
