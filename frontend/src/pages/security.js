import {keyRotation} from '../api/entities.js';
import {workspace} from '../stores/workspace.js';
import {session} from '../stores/session.js';
import {heading} from '../components/common/shell.js';
import {esc,date,notify} from '../utils/dom.js';
import {RotationStatus,KeyState,RotationKind} from '../constants/enums.js';

let timer=null;

function pct(r){return r.total?Math.round((r.migrated/r.total)*100):0;}
function keyBadge(state){const cls=state==='active'?'k-active':state==='prior'?'k-prior':'k-retired';
 return '<span class="key-badge '+cls+'">'+esc(KeyState[state]||state)+'</span>';}

export async function securityPage(){
 const {keyring,rotations}=await keyRotation.status();
 const running=rotations.find(r=>r.status==='running');
 const canAdmin=session.user.role==='admin';
 const keyCards='<div class="key-grid">'+keyring.keys.slice().reverse().map(k=>
  '<article class="key-card'+(k.id===keyring.current?' current':'')+'"><div><small>'+esc(k.id)+(k.id===keyring.current?' · 当前加密密钥':'')+'</small>'
  +'<strong>'+esc(keyring.algo)+'</strong></div>'+keyBadge(k.state)+'<span class="key-time">创建于 '+date(k.created_at)+'</span></article>').join('')+'</div>';
 const rotationList=rotations.length?rotations.map(r=>{
  const p=pct(r);
  return '<article class="rotation-card" data-id="'+r.id+'"><div class="rotation-head"><div><strong>轮换单 #'+r.id
   +'：'+esc(r.old_key_id)+' → '+esc(r.new_key_id)+'</strong><p>'+esc(RotationStatus[r.status]||r.status)
   +(r.finished_at?' · 完成于 '+date(r.finished_at):' · 发起于 '+date(r.started_at))+'</p></div>'
   +(r.status==='running'?'<span class="live-pill">进行中</span>':'<span class="done-pill">已完成</span>')+'</div>'
   +'<div class="progress"><div class="progress-bar" style="width:'+p+'%"></div></div>'
   +'<div class="rotation-numbers"><span>总量 <strong>'+r.total+'</strong></span><span>已迁 <strong>'+r.migrated+'</strong></span>'
   +'<span>待迁 <strong>'+r.pending+'</strong></span><span class="'+(r.failed?'has-fail':'')+'">失败 <strong>'+r.failed+'</strong></span>'
   +'<span>进度 <strong>'+p+'%</strong></span></div>'
   +(r.note?'<p class="rotation-note">'+esc(r.note)+'</p>':'')
   +'<div class="rotation-actions"><button class="button small" data-failures="'+r.id+'">查看失败对象</button>'
   +(r.status==='running'&&canAdmin?'<button class="button small" data-retry="'+r.id+'">重试失败对象</button>':'')
   +(r.status==='completed'?'':'')+'</div><div class="failure-list" data-failure-box="'+r.id+'"></div></article>';
 }).join(''):'<p class="empty">尚未发起过密钥轮换。</p>';
 return heading('06 / KEY SECURITY','静态加密与密钥轮换','原始工况、分析结果与简报产物均以 AES-256-GCM 静态加密；密钥材料独立保存，不随业务数据落盘。轮换期间业务照常，新写入立即使用新密钥，存量分批迁移、可中断恢复。',
  canAdmin?'<button class="button primary" id="start-rotation" '+(running?'disabled':'')+'>'+(running?'轮换进行中…':'发起密钥轮换')+'</button>':'')
  +'<section class="panel"><div class="section-title"><h2>密钥环</h2><span>仅展示密钥 ID 与状态</span></div>'
  +'<p class="hint">当前密钥：<strong>'+esc(keyring.current)+'</strong> · 算法 '+esc(keyring.algo)+'。密钥材料保存在独立密钥卷，数据库与产物中只出现密钥 ID。</p>'+keyCards+'</section>'
  +'<section class="panel"><div class="section-title"><h2>轮换记录与迁移进度</h2><span>每批 '+esc(workspace.meta?.rotation_batch_size||'—')+' 个对象 · 自动刷新</span></div>'+rotationList+'</section>';
}

async function loadFailures(id){
 const box=document.querySelector('[data-failure-box="'+id+'"]');
 const {items}=await keyRotation.failures(id);
 if(!items.length){box.innerHTML='<p class="hint">暂无失败对象。</p>';return;}
 box.innerHTML='<table class="failure-table"><thead><tr><th>类型</th><th>对象</th><th>尝试</th><th>失败原因</th><th>时间</th></tr></thead><tbody>'
  +items.map(i=>'<tr><td>'+esc(RotationKind[i.kind]||i.kind)+(i.detail?' · '+esc(i.detail):'')+'</td><td>#'+i.ref_id+'</td><td>'+i.attempts+'</td><td>'+esc(i.last_error)+'</td><td>'+date(i.updated_at)+'</td></tr>').join('')+'</tbody></table>';
}

function schedulePoll(refresh){
 clearInterval(timer);
 timer=setInterval(async()=>{
  try{
   const {rotations}=await keyRotation.status();
   if(!rotations.some(r=>r.status==='running')){clearInterval(timer);timer=null;}
   await refresh();
  }catch(e){/* 轮询失败静默，下轮再试 */}
 },3000);
}

export function bindSecurity(refresh){
 const start=document.querySelector('#start-rotation');
 if(start)start.onclick=async()=>{
  start.disabled=true;
  try{
   const r=await keyRotation.start();
   notify('轮换已发起，新写入立即使用新密钥 '+r.new_key_id);
   schedulePoll(refresh);await refresh();
  }catch(e){notify(e.message,true);start.disabled=false;}
 };
 document.querySelectorAll('[data-failures]').forEach(b=>b.onclick=()=>loadFailures(b.dataset.failures).catch(e=>notify(e.message,true)));
 document.querySelectorAll('[data-retry]').forEach(b=>b.onclick=async()=>{
  try{
   const before=await keyRotation.get(b.dataset.retry);
   const r=await keyRotation.retry(b.dataset.retry);
   notify('已把 '+before.failed+' 个失败对象重新排队');
   schedulePoll(refresh);await refresh();
  }catch(e){notify(e.message,true);}
 });
 // 页面打开时若有进行中的轮换，自动轮询
 keyRotation.status().then(({rotations})=>{if(rotations.some(r=>r.status==='running'))schedulePoll(refresh);}).catch(()=>{});
}
