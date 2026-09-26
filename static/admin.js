const state = JSON.parse(document.getElementById('initialConfig').textContent || '{}');
state.elements = Array.isArray(state.elements) ? state.elements : [];
let selectedId = null;
let dragging = null;
const canvas = document.getElementById('canvas');
const inspector = document.getElementById('inspector');
const deleteBtn = document.getElementById('deleteBtn');
const statusBox = document.getElementById('status');
const clamp = (value, min, max) => Math.max(min, Math.min(max, Number(value) || 0));
const selected = () => state.elements.find(item => item.id === selectedId);
function makeId(){ return 'item-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2,7); }
function addItem(type){
  const item = {id:makeId(), type:type, text:type === 'text' ? 'اكتب هنا' : '', src:'', x:10, y:10, w:type === 'image' ? 30 : 70, h:type === 'image' ? 35 : 14, color:'#ffffff', background:type === 'shape' ? state.accent : 'transparent', fontSize:30, radius:14, align:'center'};
  state.elements.push(item); selectedId=item.id; render();
}
function styleItem(item, el){
  el.style.left = item.x + '%'; el.style.top = item.y + '%'; el.style.width = item.w + '%'; el.style.height = item.h + '%';
  el.style.color = item.color || '#fff'; el.style.background = item.type === 'shape' ? 'transparent' : (item.background || 'transparent');
  el.style.fontSize = (item.fontSize || 30) + 'px'; el.style.borderRadius = (item.radius || 0) + 'px'; el.style.textAlign = item.align || 'center';
  el.style.setProperty('--shape-color', item.background || state.accent);
}
function render(){
  canvas.innerHTML='';
  if(!state.elements.length){ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='اضغط نص أو صورة أو شكل للبدء'; canvas.appendChild(empty); }
  state.elements.forEach(item=>{
    const el=document.createElement('div'); el.className='editor-item' + (item.id===selectedId ? ' selected':''); el.dataset.id=item.id; styleItem(item,el);
    if(item.type==='image' && item.src){ const img=document.createElement('img'); img.src=item.src; el.appendChild(img); }
    else if(item.type==='shape'){ const shape=document.createElement('span'); shape.className='editor-shape'; el.appendChild(shape); }
    else { el.textContent=item.text || 'نص'; }
    el.addEventListener('click', e=>{ e.stopPropagation(); selectedId=item.id; render(); });
    el.addEventListener('pointerdown', e=>{ if(e.button!==undefined && e.button!==0) return; selectedId=item.id; const rect=canvas.getBoundingClientRect(); dragging={item:item,startX:e.clientX,startY:e.clientY,startLeft:item.x,startTop:item.y,rect:rect,el:el}; el.setPointerCapture(e.pointerId); el.classList.add('selected'); });
    el.addEventListener('pointermove', e=>{ if(!dragging || dragging.item.id!==item.id) return; item.x=clamp(dragging.startLeft + ((e.clientX-dragging.startX)/dragging.rect.width)*100,0,100-item.w); item.y=clamp(dragging.startTop + ((e.clientY-dragging.startY)/dragging.rect.height)*100,0,100-item.h); styleItem(item,el); updateInspectorValues(); });
    el.addEventListener('pointerup', ()=>{ dragging=null; });
    canvas.appendChild(el);
  });
  renderInspector();
}
function field(label,id,value,type='text'){
  return '<div class="field"><label>'+label+'</label><input id="'+id+'" type="'+type+'" value="'+String(value ?? '').replace(/"/g,'&quot;')+'"></div>';
}
function renderInspector(){
  const item=selected(); deleteBtn.style.display=item?'block':'none';
  if(!item){ inspector.innerHTML='<p class="hint">اضغط على أي عنصر في اللوحة لتعديله أو سحبه.</p>'; return; }
  let html='';
  if(item.type==='text') html += '<div class="field"><label>النص</label><textarea id="editText">'+(item.text||'')+'</textarea></div>';
  if(item.type==='image') html += '<div class="field"><label>رابط الصورة</label><input id="editSrc" value="'+(item.src||'')+'"></div>';
  html += '<div class="two">'+field('الموضع الأفقي %','editX',item.x,'number')+field('الموضع العمودي %','editY',item.y,'number')+'</div>';
  html += '<div class="two">'+field('العرض %','editW',item.w,'number')+field('الارتفاع %','editH',item.h,'number')+'</div>';
  html += '<div class="two">'+field('حجم الخط','editFont',item.fontSize,'number')+field('استدارة الزوايا','editRadius',item.radius,'number')+'</div>';
  html += '<div class="two"><div class="field"><label>لون النص</label><input id="editColor" type="color" value="'+(item.color||'#ffffff')+'"></div><div class="field"><label>لون الخلفية</label><input id="editBg" type="color" value="'+(item.background && item.background[0]==='#' ? item.background : '#031613')+'"></div></div>';
  inspector.innerHTML=html;
  ['editText','editSrc','editX','editY','editW','editH','editFont','editRadius','editColor','editBg'].forEach(id=>{ const node=document.getElementById(id); if(node) node.addEventListener('input',()=>{ updateFromInspector(); }); });
}
function updateFromInspector(){ const item=selected(); if(!item) return; const get=id=>document.getElementById(id); if(get('editText')) item.text=get('editText').value; if(get('editSrc')) item.src=get('editSrc').value; if(get('editX')) item.x=clamp(get('editX').value,0,100-item.w); if(get('editY')) item.y=clamp(get('editY').value,0,100-item.h); if(get('editW')) item.w=clamp(get('editW').value,5,100-item.x); if(get('editH')) item.h=clamp(get('editH').value,5,100-item.y); if(get('editFont')) item.fontSize=clamp(get('editFont').value,8,120); if(get('editRadius')) item.radius=clamp(get('editRadius').value,0,100); if(get('editColor')) item.color=get('editColor').value; if(get('editBg')) item.background=get('editBg').value; render(); }
function updateInspectorValues(){ const item=selected(); if(!item) return; const values={editX:item.x,editY:item.y,editW:item.w,editH:item.h}; Object.keys(values).forEach(id=>{const node=document.getElementById(id);if(node)node.value=values[id];}); }
document.getElementById('addText').onclick=()=>addItem('text');
document.getElementById('addShape').onclick=()=>addItem('shape');
document.getElementById('addImage').onclick=()=>document.getElementById('imagePicker').click();
document.getElementById('imagePicker').onchange=async e=>{ const file=e.target.files[0]; if(!file)return; const form=new FormData(); form.append('image',file); statusBox.textContent='جاري رفع الصورة...'; const response=await fetch('/api/upload',{method:'POST',body:form}); const data=await response.json(); if(!response.ok){statusBox.textContent=data.error||'تعذر رفع الصورة';return;} const item={id:makeId(),type:'image',src:data.url,x:10,y:10,w:35,h:35,color:'#fff',background:'transparent',fontSize:20,radius:14,align:'center'}; state.elements.push(item); selectedId=item.id; statusBox.textContent='تمت إضافة الصورة'; render(); e.target.value=''; };
deleteBtn.onclick=()=>{ state.elements=state.elements.filter(item=>item.id!==selectedId); selectedId=null; render(); };
document.getElementById('saveBtn').onclick=async()=>{ state.site_name=document.getElementById('siteName').value; state.developer=document.getElementById('developer').value; state.tagline=document.getElementById('tagline').value; state.background=document.getElementById('background').value; state.accent=document.getElementById('accent').value; statusBox.textContent='جاري الحفظ...'; const response=await fetch('/api/site-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(state)}); statusBox.textContent=response.ok?'تم حفظ الموقع بنجاح':'تعذر الحفظ'; };
canvas.addEventListener('click',()=>{selectedId=null;render();});
render();
