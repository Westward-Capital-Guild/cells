import React from 'react';
import {FlatButton, RaisedButton, TextField} from 'material-ui';
import PydioApi from 'pydio/http/api';

export default class DevicePasswordPanel extends React.Component {
    state = {label: '', secret: '', createdId: '', devices: [], username: '', busy: true, error: '', notice: '', pendingRevoke: ''};

    componentDidMount() {
        this.active = true;
        this.refresh().catch(() => this.update({error: '无法加载设备，请重新打开此面板重试。'}))
            .finally(() => this.update({busy: false}));
    }

    componentWillUnmount() { this.active = false; }
    update = values => { if (this.active) this.setState(values); };
    request = (type, fields = {}) => PydioApi.getRestClient().devicePasswordRequest(type, fields);
    refresh = () => this.request('device_password_list').then(data => {
        if (!data.TriggerInfo || !data.TriggerInfo.username) throw new Error('Missing user identity');
        this.update({username: data.TriggerInfo.username, devices: JSON.parse(data.TriggerInfo.devices || '[]')});
    });

    create = async () => {
        if (this.state.busy || this.state.secret || !this.state.label.trim() || !this.state.username) return;
        this.update({busy: true, error: '', notice: ''});
        try {
            const data = await this.request('device_password_create', {label: this.state.label.trim()});
            if (!data.Token || !data.Token.AccessToken || !data.TriggerInfo || !data.TriggerInfo.id) throw new Error('Missing device password');
            this.update({secret: data.Token.AccessToken, createdId: data.TriggerInfo.id, label: ''});
            try { await this.refresh(); } catch (_) { this.update({error: '密码已创建，但列表刷新失败。请先保存密码，再重新打开面板。'}); }
        } catch (_) { this.update({error: '创建设备密码失败，请重试。'}); }
        finally { this.update({busy: false}); }
    };

    revoke = async id => {
        if (this.state.busy || this.state.pendingRevoke !== id) return;
        this.update({busy: true, error: '', notice: ''});
        try {
            await this.request('device_password_revoke', {id});
            this.update({devices: this.state.devices.filter(d => d.id !== id), pendingRevoke: '',
                ...(this.state.createdId === id ? {secret: '', createdId: ''} : {}),
                notice: '设备密码已撤销。正在使用的连接可能延迟失效。'});
        } catch (_) { this.update({error: '撤销失败，设备密码仍可能有效，请重试。'}); }
        finally { this.update({busy: false}); }
    };

    copy = async value => {
        try {
            await navigator.clipboard.writeText(value);
            this.update({notice: '已复制', error: ''});
        } catch (_) { this.update({error: '浏览器不允许自动复制，请选中内容手动复制。'}); }
    };

    render() {
        const {username, secret, label, devices, busy, error, notice, pendingRevoke} = this.state;
        const repositories = [];
        this.props.pydio.user.getRepositoriesList().forEach(repo => {
            if (repo.getAccessType() === 'gateway' && repo.getSlug()) repositories.push(repo);
        });
        const root = window.location.origin + '/dav/';
        const field = (title, value) => <div style={{marginBottom: 8}}>
            <div>{title}</div><div style={{display: 'flex', alignItems: 'center', gap: 8}}>
                <input aria-label={title} value={value} readOnly style={{flex: 1, minWidth: 0, padding: 8}}/>
                <FlatButton label="复制" onClick={() => this.copy(value)} disabled={!value}/>
            </div>
        </div>;
        return <section style={{padding: 20}} aria-label="连接电脑 / WebDAV">
            <h3 style={{marginTop: 0}}>连接电脑 / WebDAV</h3>
            <p>每台电脑使用独立的设备密码。访问权限与当前账号相同，包括可访问的共享区和自己的个人区。</p>
            {field('用户名（请原样使用，不是显示姓名或邮箱）', username)}
            {field('所有可访问文件区', root)}
            {repositories.map(repo => <React.Fragment key={repo.getId()}>{field(repo.getLabel(), root + encodeURIComponent(repo.getSlug()) + '/')}</React.Fragment>)}
            <p>设备密码连续 180 天未通过服务器认证后过期，认证成功会延长有效期。退出网页登录不会删除设备密码。</p>
            {secret ? <div style={{background: '#f2f7fc', padding: 12}}>
                <strong>密码只在本次创建后显示，关闭面板后无法找回。</strong>
                {field('新设备密码', secret)}
                <FlatButton label="我已保存，隐藏密码" onClick={() => this.update({secret: '', createdId: '', notice: ''})}/>
            </div> : <div>
                <TextField floatingLabelText="设备名称" hintText="例如：我的 Mac" value={label} maxLength={80}
                    onChange={e => this.update({label: e.target.value})} disabled={busy}/>
                <RaisedButton label={busy ? '处理中…' : '创建设备密码'} primary disabled={busy || !username || !label.trim()} onClick={this.create}/>
                {!busy && !label.trim() && <div role="status" style={{color: '#666', marginTop: 4}}>请先输入设备名称，例如“我的电脑”。</div>}
            </div>}
            <h4>设备密码管理</h4>
            {!devices.length && <p>{busy ? '正在加载…' : '尚未创建设备密码。'}</p>}
            {devices.map(device => <div key={device.id} style={{padding: '10px 0', borderBottom: '1px solid #eee'}}>
                <strong>{device.name}</strong>
                <div>创建于 {new Date(device.createdAt * 1000).toLocaleString()} · 当前有效期至 {new Date(device.expiresAt * 1000).toLocaleString()}</div>
                {pendingRevoke === device.id ? <div>
                    <span>确认撤销“{device.name}”？该设备重新连接时将需要新密码。</span>
                    <FlatButton label="确认撤销" secondary disabled={busy} onClick={() => this.revoke(device.id)}/>
                    <FlatButton label="取消" disabled={busy} onClick={() => this.update({pendingRevoke: ''})}/>
                </div> : <FlatButton label="撤销" disabled={busy} onClick={() => this.update({pendingRevoke: device.id})}/>}
            </div>)}
            {error && <p role="alert" style={{color: '#b71c1c'}}>{error}</p>}
            {notice && <p role="status">{notice}</p>}
        </section>;
    }
}
