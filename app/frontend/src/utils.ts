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

export function securityEventDescription(event: string): string {
  return ({
    unknown_host: '未登録のホスト名への通信を404で拒否しました',
    rate_limited: '送信元IPからの過剰なリクエストを429で拒否しました',
    temporarily_blocked: '上限超過を繰り返した送信元IPを5分間遮断しました',
    connection_limited: '同時接続数を超えた新規接続を拒否しました',
    authorization_denied: '未登録鍵または未予約の公開先への接続を拒否しました',
  } as Record<string, string>)[event] ?? '検知して記録しました';
}
