const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {createRequire} = require('node:module');

const gui = createRequire(path.resolve(__dirname, '../gui.ajax/package.json'));
const babel = gui('@babel/core');
const React = gui('react');
const settle = () => new Promise(resolve => setImmediate(resolve));

// Load the shipped component source; substitute only its application boundaries.
function load(file, dependencies, globals = {}) {
    const filename = path.resolve(__dirname, '..', file);
    const {code} = babel.transformSync(fs.readFileSync(filename, 'utf8'), {
        filename, babelrc: false, configFile: false,
        presets: [gui.resolve('@babel/preset-react'),
            [gui.resolve('@babel/preset-env'), {targets: {node: 'current'}}]],
    });
    const exports = {};
    vm.runInNewContext(code, {
        exports, React, ...globals,
        require(name) {
            if (Object.hasOwn(dependencies, name)) return dependencies[name];
            if (name.startsWith('.')) {
                return load(path.relative(path.resolve(__dirname, '..'),
                    path.resolve(path.dirname(filename), name + '.js')), dependencies, globals);
            }
            return gui(name);
        },
    }, {filename});
    return exports;
}

function callback(client, pydio, navigations) {
    const {default: wrapper} = load('gui.ajax/res/js/ui/ReactUI/router/LoginCallbackRouter.js', {
        'pydio/http/api': {getRestClient: () => client},
        'react-router/lib/browserHistory': {replace: url => navigations.push(url)},
    }, {sessionStorage: {getItem: () => null, removeItem() {}}});
    const Component = wrapper(pydio);
    return new Component({location: {search: '?code=synthetic-single-use-code'}});
}

for (const pathname of ['/auth/callback', '/login/callback']) {
    test(`actual router exchanges the code at ${pathname} instead of selecting a workspace`, async () => {
        let exchanges = 0;
        const ignored = () => () => null;
        const dependencies = {
            './MainRouter': ignored, './HomepageRouter': ignored,
            './WorkspaceRouter': ignored, './PathRouter': ignored,
            './LoginRouter': ignored, './LogoutRouter': ignored,
            './LogoutCallbackRouter': ignored,
            './OAuthRouter': {OAuthLoginRouter: ignored, OAuthOOBRouter: ignored,
                OAuthFallbacksRouter: ignored},
            'react-router/lib/browserHistory': {replace() {}},
            'pydio/http/api': {getRestClient: () => ({sessionLoginWithAuthCode(code) {
                assert.equal(code, 'synthetic-code');
                exchanges++;
                return new Promise(() => {});
            }})},
        };
        const {default: Router} = load('gui.ajax/res/js/ui/ReactUI/router/Router.js',
            dependencies, {sessionStorage: {getItem: () => null, removeItem() {}}});
        const routes = new Router({pydio: {}}).render().props.routes;
        const props = await new Promise((resolve, reject) => {
            gui('react-router').match({routes, location: pathname + '?code=synthetic-code'},
                (error, redirect, props) => error ? reject(error) : resolve(props));
        });
        assert.ok(props);
        const Component = props.components.filter(Boolean).at(-1);
        const component = new Component({location: props.location});
        component.componentDidMount();
        component.render();
        component.render();
        assert.equal(exchanges, 1);
    });
}

test('rendering the callback repeatedly exchanges a single-use code only once', () => {
    let exchanges = 0;
    const component = callback({sessionLoginWithAuthCode() {
        exchanges++;
        return new Promise(() => {});
    }}, {}, []);
    if (component.componentDidMount) component.componentDidMount();
    component.render();
    component.render();
    assert.equal(exchanges, 1);
});

test('successful exchange reloads the registry without dismissing an unrelated modal', async () => {
    let registryLoads = 0;
    const navigations = [];
    const component = callback({
        sessionLoginWithAuthCode: () => Promise.resolve(),
        getOrUpdateJwt: () => Promise.resolve('synthetic-token'),
    }, {
        UI: {closeCurrentModal() {throw new Error('must not close arbitrary modals');}},
        loadXmlRegistry() {registryLoads++;},
    }, navigations);
    component.componentDidMount();
    await settle();
    assert.equal(registryLoads, 1);
    assert.deepEqual(navigations, ['/']);
});

test('rejected exchange returns to login without retaining the failed code', async () => {
    const navigations = [];
    const component = callback({
        sessionLoginWithAuthCode: () => Promise.reject(new Error('invalid_grant')),
    }, {}, navigations);
    component.componentDidMount();
    await settle();
    assert.deepEqual(navigations, ['/login']);
});

function loginDialog(currentUser = null, oidcOnly = true) {
    const listeners = new Set();
    const pydio = {
        user: currentUser,
        observe(event, fn) {assert.equal(event, 'user_logged'); listeners.add(fn);},
        stopObserving(event, fn) {assert.equal(event, 'user_logged'); listeners.delete(fn);},
    };
    const {LoginPasswordDialog: lifecycle} = load('core.authfront/res/js/index.js', {
        pydio: {getInstance: () => pydio, requireLib: () => ({})},
        'pydio/http/api': {},
        'cells-sdk': {},
        'create-react-class': spec => spec,
        'material-ui': {},
        'material-ui/styles': {muiThemeable: () => component => component},
    }, {PydioReactUI: {}});
    let dismissals = 0;
    const dialog = {...lifecycle,
        state: {globalParameters: new Map([
            ['externalIdentity', {enabled: oidcOnly, passwordLoginEnabled: !oidcOnly,
                loginURL: '/auth/oidc/login'}],
        ])},
        dismiss() {dismissals++;}};
    return {dialog, listeners, count: () => dismissals};
}

test('login dialog dismisses on authenticated registry load, not on anonymous load', () => {
    const {dialog, listeners, count} = loginDialog();
    dialog.componentDidMount();
    for (const listener of listeners) listener(null);
    assert.equal(count(), 0);
    for (const listener of listeners) listener({id: 'synthetic-user'});
    assert.equal(count(), 1);
    dialog.componentWillUnmount();
    assert.equal(listeners.size, 0);
});

test('late-loading login dialog dismisses when registry already has a user', () => {
    const {dialog, count} = loginDialog({id: 'synthetic-user'});
    dialog.componentDidMount();
    assert.equal(count(), 1);
    dialog.componentWillUnmount();
});

test('native password dialogs do not get the OIDC-only auto-dismiss behavior', () => {
    const {dialog, listeners, count} = loginDialog({id: 'synthetic-user'}, false);
    dialog.componentDidMount();
    assert.equal(listeners.size, 0);
    assert.equal(count(), 0);
    dialog.componentWillUnmount();
});
