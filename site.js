
(function(){
  function num(v){
    if(v===undefined||v===null)return NaN;
    var s=String(v).replace(/[\s$,%]/g,'').replace(/\u2212/g,'-');
    if(s===''||s==='\u2014'||s==='-')return NaN;
    if(/^\d{4}-\d\d-\d\d/.test(s))return NaN;   // a date is compared as a string (ISO sorts oldest->newest)
    var n=parseFloat(s);
    return isNaN(n)?NaN:n;
  }
  function upgrade(w){
    var t=w.querySelector('table');
    if(!t||!t.tHead||!t.tBodies.length)return;
    var head=t.tHead.rows[0],body=t.tBodies[0];
    var rows=[].slice.call(body.rows);
    if(!rows.length)return;
    var cols=[].slice.call(head.cells);
    // a table may open already sorted (newest first for dated lists): data-sort="column" data-dir="desc"
    var st={q:'',sort:w.dataset.sort===undefined?-1:+w.dataset.sort,dir:w.dataset.dir==='desc'?-1:1,page:1,size:+(w.dataset.size||20),group:-1};
    var bar=document.createElement('div');
    bar.className='dtb';
    var q=document.createElement('input');
    q.type='search';q.className='dtq';
    q.placeholder=w.dataset.filter||'Filter rows';
    q.setAttribute('aria-label',w.dataset.filter||'Filter rows');
    var lab=document.createElement('label');
    var gsel=document.createElement('select');
    gsel.className='dtgsel';
    gsel.setAttribute('aria-label',w.dataset.groupLabel||'Group by');
    gsel.innerHTML='<option value="-1">'+(w.dataset.noGroup||'No grouping')+'</option>'+
      cols.map(function(c,i){return '<option value="'+i+'">'+c.textContent.trim()+'</option>'}).join('');
    lab.appendChild(document.createTextNode((w.dataset.groupLabel||'Group by')+' '));
    lab.appendChild(gsel);
    var cnt=document.createElement('span');
    cnt.className='dtcount';cnt.setAttribute('aria-live','polite');
    var pager=document.createElement('span');
    pager.className='dtpager';
    var prev=document.createElement('button');
    prev.type='button';prev.textContent=w.dataset.prev||'Previous';
    var next=document.createElement('button');
    next.type='button';next.textContent=w.dataset.next||'Next';
    var info=document.createElement('span');
    info.className='dtinfo';
    pager.appendChild(prev);pager.appendChild(info);pager.appendChild(next);
    bar.appendChild(q);bar.appendChild(lab);bar.appendChild(cnt);bar.appendChild(pager);
    w.parentNode.insertBefore(bar,w);
    function key(r,i){
      var c=r.cells[i];
      if(!c)return '';
      return c.dataset.v!==undefined?c.dataset.v:c.textContent.trim();
    }
    function filtered(){
      var words=st.q.toLowerCase().split(/\s+/).filter(Boolean);
      if(!words.length)return rows.slice();
      return rows.filter(function(r){
        var s=r.textContent.toLowerCase();
        return words.every(function(x){return s.indexOf(x)>=0});
      });
    }
    function sorted(list){
      if(st.group>=0){
        list=list.slice().sort(function(a,b){return key(a,st.group).localeCompare(key(b,st.group))});
      }
      if(st.sort<0)return list;
      var i=st.sort;
      return list.slice().sort(function(a,b){
        var x=key(a,i),y=key(b,i),nx=num(x),ny=num(y),d;
        // unknown always sinks to the bottom, in both directions: a dash is not "the oldest" or "the newest"
        if(x===''||x==='\u2014')return 1;
        if(y===''||y==='\u2014')return -1;
        if(!isNaN(nx)&&!isNaN(ny)){d=nx-ny}
        else{d=x.localeCompare(y)}
        return d*st.dir;
      });
    }
    function draw(){
      var list=sorted(filtered()),total=list.length;
      var pages=Math.max(1,Math.ceil(total/st.size));
      if(st.page>pages)st.page=pages;
      var start=(st.page-1)*st.size,end=Math.min(start+st.size,total);
      var frag=document.createDocumentFragment(),last=null;
      [].slice.call(body.rows).forEach(function(r){body.removeChild(r)});
      if(!total){
        var tr=document.createElement('tr'),td=document.createElement('td');
        td.colSpan=cols.length;td.className='mut';td.textContent=w.dataset.empty||'No row matches.';
        tr.appendChild(td);frag.appendChild(tr);
      }
      list.slice(start,end).forEach(function(r){
        if(st.group>=0){
          var g=key(r,st.group);
          if(g!==last){
            last=g;
            var gr=document.createElement('tr');gr.className='dtgrp';
            var gd=document.createElement('td');gd.colSpan=cols.length;
            gd.textContent=(g===''||g==='\u2014')?(w.dataset.unknown||'Unknown'):g;
            gr.appendChild(gd);frag.appendChild(gr);
          }
        }
        frag.appendChild(r);
      });
      body.appendChild(frag);
      cnt.textContent=total+' '+(w.dataset.rowsLabel||'rows');
      info.textContent=total?((start+1)+'\u2013'+end+' / '+total):'';
      prev.disabled=st.page<=1;
      next.disabled=st.page>=pages;
      pager.style.display=pages>1?'flex':'none';
    }
    if(st.sort>=0&&cols[st.sort])cols[st.sort].setAttribute('aria-sort',st.dir===1?'ascending':'descending');
    cols.forEach(function(h,i){
      if(h.dataset.nosort)return;
      h.tabIndex=0;
      h.setAttribute('role','button');
      function go(){
        if(st.sort===i){
          if(st.dir===1){st.dir=-1}else{st.sort=-1;st.dir=1}
        }else{st.sort=i;st.dir=1}
        cols.forEach(function(x){x.removeAttribute('aria-sort')});
        if(st.sort===i)h.setAttribute('aria-sort',st.dir===1?'ascending':'descending');
        st.page=1;draw();
      }
      h.addEventListener('click',go);
      h.addEventListener('keydown',function(e){
        if(e.key==='Enter'||e.key===' '){e.preventDefault();go()}
      });
    });
    q.addEventListener('input',function(){st.q=q.value;st.page=1;draw()});
    gsel.addEventListener('change',function(){st.group=+gsel.value;st.page=1;draw()});
    prev.addEventListener('click',function(){if(st.page>1){st.page--;draw()}});
    next.addEventListener('click',function(){st.page++;draw();if(st.page>Math.ceil(filtered().length/st.size))draw()});
    draw();
  }
  try{[].slice.call(document.querySelectorAll('div.tw')).forEach(upgrade)}catch(e){}
})();
