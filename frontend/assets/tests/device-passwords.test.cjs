const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {createRequire} = require('node:module');
const gui = createRequire(path.resolve(__dirname, '../gui.ajax/package.json'));
const React = gui('react');
function panel(api, clipboard = {writeText: async () => {}}) {
    const filename = path.resolve(__dirname, '../action.user/res/js/DevicePasswordPanel.js');
    const {code} = gui('@babel/core').transformSync(fs.readFileSync(filename, 'utf8'), {filename, babelrc:false, configFile:false,
        presets:[gui.resolve('@babel/preset-react'), [gui.resolve('@babel/preset-env'), {targets:{node:'current'}}]]});
    const exports = {};
    vm.runInNewContext(code, {exports, navigator:{clipboard}, window:{location:{origin:'https://files.example.test'}},
        require(name) { if(name==='pydio/http/api') return {getRestClient:()=>({devicePasswordRequest:api})};
            if(name==='material-ui') return {FlatButton:'button', RaisedButton:'button', TextField:'input'};
            return gui(name); }});
    const instance = new exports.default({pydio:{user:{getRepositoriesList:()=>new Map()}}});
    instance.active=true;
    instance.setState = changes => Object.assign(instance.state,changes);
    return instance;
}
test('create retains a one-time secret without replacing the browser session; reopen lists metadata', async()=>{
    const calls=[];
    const api=async(type,fields)=>{calls.push([type,fields]);return type==='device_password_create'
        ? {Token:{AccessToken:'synthetic'},TriggerInfo:{id:'mine'}}
        : {TriggerInfo:{username:'exact-login',devices:'[{"id":"mine","name":"My Mac"}]'}};};
    const p=panel(api);await p.refresh();p.state.busy=false;p.state.label='My Mac';await p.create();
    assert.equal(p.state.secret,'synthetic');assert.equal(p.state.username,'exact-login');
    const reopened=panel(api);await reopened.refresh();assert.equal(reopened.state.secret,'');assert.equal(reopened.state.devices[0].id,'mine');
    assert.deepEqual(calls.map(c=>c[0]),['device_password_list','device_password_create','device_password_list','device_password_list']);
});
test('revoke uses the selected stable ID, confirmation required, other devices remain', async()=>{
    const calls=[];const p=panel(async(type,fields)=>calls.push([type,fields.id]));p.state.busy=false;
    p.state.devices=[{id:'first'},{id:'second'}];
    await p.revoke('second');assert.equal(calls.length,0);
    p.state.pendingRevoke='second';await p.revoke('second');
    assert.deepEqual(calls,[['device_password_revoke','second']]);assert.equal(p.state.devices[0].id,'first');assert.equal(p.state.devices.length,1);
});
test('clipboard rejection shows manual-copy fallback without claiming success', async()=>{
    const p=panel(async()=>{}, {writeText:async()=>{throw new Error('denied');}});await p.copy('synthetic');
    assert.match(p.state.error,/手动复制/);assert.equal(p.state.notice,'');
});
test('failed revocation leaves device intact and informs the user', async()=>{
    const p=panel(async()=>{throw new Error('offline');});p.state.busy=false;p.state.pendingRevoke='mine';p.state.devices=[{id:'mine'}];
    await p.revoke('mine');assert.equal(p.state.devices.length,1);assert.match(p.state.error,/撤销失败/);
});
