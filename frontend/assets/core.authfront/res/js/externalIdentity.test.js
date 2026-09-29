import { describe, expect, it, vi } from 'vitest';

import {
    isExternalIdentityOnly,
    externalLoginURL,
    logoutApplication,
    normalizeExternalIdentityConfig,
} from './externalIdentity';

describe('external identity configuration', () => {
    it('keeps upstream password login behavior by default', () => {
        const config = normalizeExternalIdentityConfig();
        expect(config.enabled).toBe(false);
        expect(config.passwordLoginEnabled).toBe(true);
        expect(isExternalIdentityOnly(config)).toBe(false);
    });

    it('recognizes an OIDC-only browser login', () => {
        const config = normalizeExternalIdentityConfig({
            enabled: true,
            passwordLoginEnabled: false,
            loginURL: '/auth/oidc/login',
            loginButtonLabel: 'Use Passport',
        });
        expect(isExternalIdentityOnly(config)).toBe(true);
        expect(config.loginButtonLabel).toBe('Use Passport');
    });
});

describe('external login challenge handoff', () => {
    it('preserves the OAuth login challenge when leaving the Cells login page', () => {
        expect(externalLoginURL('/auth/oidc/login', 'https://files.example.com/oauth2/login?login_challenge=challenge-123'))
            .toBe('https://files.example.com/auth/oidc/login?login_challenge=challenge-123');
    });

    it('does not add a challenge to normal login navigation', () => {
        expect(externalLoginURL('/auth/oidc/login', 'https://files.example.com/login'))
            .toBe('/auth/oidc/login');
    });
});

describe('logoutApplication', () => {
    it('clears the Cells session before navigating to the application signed-out page', async () => {
        const events = [];
        const sessionLogout = vi.fn(() => {
            events.push('cells-session-cleared');
            return Promise.resolve();
        });
        const loadLocalRegistry = vi.fn();
        const navigate = vi.fn(() => events.push('passport-navigation'));
        await logoutApplication({
            enabled: true,
            logoutURL: 'https://passport.example.com/auth/edge/signed-out?application_id=files',
        }, sessionLogout, loadLocalRegistry, navigate);

        expect(sessionLogout).toHaveBeenCalledOnce();
        expect(navigate).toHaveBeenCalledWith('https://passport.example.com/auth/edge/signed-out?application_id=files');
        expect(loadLocalRegistry).not.toHaveBeenCalled();
        expect(events).toEqual(['cells-session-cleared', 'passport-navigation']);
    });

    it('keeps the native Cells refresh behavior when no logout URL is configured', async () => {
        const sessionLogout = vi.fn(() => Promise.resolve());
        const loadLocalRegistry = vi.fn(() => Promise.resolve());
        const navigate = vi.fn();
        await logoutApplication({enabled: false, logoutURL: ''}, sessionLogout, loadLocalRegistry, navigate);

        expect(sessionLogout).toHaveBeenCalledOnce();
        expect(loadLocalRegistry).toHaveBeenCalledOnce();
        expect(navigate).not.toHaveBeenCalled();
    });

    it('does not navigate to Passport when clearing the Cells session fails', async () => {
        const error = new Error('logout failed');
        const navigate = vi.fn();
        await expect(logoutApplication(
            {enabled: true, logoutURL: 'https://passport.example.com/auth/edge/signed-out'},
            () => Promise.reject(error),
            vi.fn(),
            navigate,
        )).rejects.toBe(error);
        expect(navigate).not.toHaveBeenCalled();
    });
});
