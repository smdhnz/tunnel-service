import { describe, expect, it } from 'vitest';
import { formatLocalDate, securityEventLabel } from './utils';

describe('UI formatting', () => {
  it('formats API timestamps in the requested local timezone', () => {
    expect(formatLocalDate('2024-01-02T03:04:05Z', 'Asia/Tokyo')).toContain('12:04:05');
  });
  it('keeps known security-event wording', () => {
    expect(securityEventLabel('authorization_denied')).toBe('認証・認可の拒否');
    expect(securityEventLabel('future_event')).toBe('future_event');
  });
});
