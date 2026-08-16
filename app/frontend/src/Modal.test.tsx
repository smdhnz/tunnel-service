// @vitest-environment jsdom
import { act } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { Modal } from './App';

beforeAll(() => {
  HTMLDialogElement.prototype.showModal = function showModal() { this.setAttribute('open', ''); };
  HTMLDialogElement.prototype.close = function close() { this.removeAttribute('open'); };
});

describe('作成modal', () => {
  it('失敗時は開いたまま入力を保持する', async () => {
    const user = userEvent.setup();
    const close = vi.fn();
    const submit = vi.fn().mockResolvedValue(false);
    render(<Modal open onClose={close} title="追加" eyebrow="新規" submitLabel="追加" onSubmit={submit}><label>名前<input name="name" /></label></Modal>);

    const input = screen.getByRole('textbox') as HTMLInputElement;
    await user.type(input, '保持する値');
    await user.click(screen.getByRole('button', { name: '追加' }));

    expect(submit).toHaveBeenCalledTimes(1);
    expect(close).not.toHaveBeenCalled();
    expect(input.value).toBe('保持する値');
    expect(screen.getByRole('dialog').hasAttribute('open')).toBe(true);
  });

  it('送信中の二重送信を防ぎ、成功時だけ閉じる', async () => {
    const user = userEvent.setup();
    const close = vi.fn();
    let resolve: (ok: boolean) => void = () => undefined;
    const submit = vi.fn(() => new Promise<boolean>((done) => { resolve = done; }));
    render(<Modal open onClose={close} title="予約" eyebrow="新規" submitLabel="予約" onSubmit={submit}><input name="name" /></Modal>);

    await user.click(screen.getByRole('button', { name: '予約' }));
    const sending = screen.getByRole('button', { name: '送信中…' }) as HTMLButtonElement;
    expect(sending.disabled).toBe(true);
    await user.click(sending);
    expect(submit).toHaveBeenCalledTimes(1);

    await act(async () => resolve(true));
    expect(close).toHaveBeenCalledTimes(1);
  });
});
