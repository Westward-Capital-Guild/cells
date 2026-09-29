export function normalizeExternalIdentityConfig(value) {
    const config = value && typeof value === 'object' ? value : {};
    return {
        enabled: config.enabled === true,
        passwordLoginEnabled: config.passwordLoginEnabled !== false,
        loginURL: typeof config.loginURL === 'string' ? config.loginURL : '',
        loginButtonLabel: typeof config.loginButtonLabel === 'string' && config.loginButtonLabel.trim()
            ? config.loginButtonLabel
            : 'Continue with single sign-on',
        logoutURL: typeof config.logoutURL === 'string' ? config.logoutURL : '',
    };
}

export function isExternalIdentityOnly(config) {
    return config.enabled && !config.passwordLoginEnabled && !!config.loginURL;
}

export function externalLoginURL(loginURL, currentLocation = '') {
    if (!loginURL || !currentLocation) {
        return loginURL;
    }
    const current = new URL(currentLocation, 'http://localhost');
    const challenge = current.searchParams.get('login_challenge');
    if (!challenge) {
        return loginURL;
    }
    const target = new URL(loginURL, current.origin);
    target.searchParams.set('login_challenge', challenge);
    return target.toString();
}

export function completeApplicationLogout(config, loadLocalRegistry, navigate) {
    if (config.enabled && config.logoutURL) {
        navigate(config.logoutURL);
        return Promise.resolve();
    }
    return loadLocalRegistry();
}

export function logoutApplication(config, sessionLogout, loadLocalRegistry, navigate) {
    return sessionLogout().then(() => completeApplicationLogout(config, loadLocalRegistry, navigate));
}
