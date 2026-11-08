/* 단지 브리핑 — data/brief.enc 를 비밀번호로 복호화해 보여준다.
 * 암호화 형식은 master/brief.py 와 같다: PBKDF2-SHA256 → AES-256-GCM.
 * '이 기기에서 기억'은 비밀번호가 아니라 도출된 키를 저장한다. */
(() => {
  "use strict";
  const KEY_STORE = "nlb.key.v1";
  const POS_STORE = "nlb.position";
  const STALE_HOURS = 36;
  const POSITIONS = [
    { id: "buyer", label: "매수 손님 응대" },
    { id: "hunter", label: "급매 발굴" },
    { id: "seller", label: "매도 영업·가격 상담" },
    { id: "market", label: "시장 브리핑·콘텐츠" },
  ];
  const $ = (s) => document.querySelector(s);
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* 저장 불가 환경 */ } },
    del(k) { try { localStorage.removeItem(k); } catch { /* */ } },
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const man = (won) => (won ? Math.round(won / 10000).toLocaleString("ko-KR") : "");
  const pct = (v) => (v == null ? "" : `${v > 0 ? "+" : ""}${(v * 100).toFixed(1)}%`);

  let enc = null;
  let data = null;

  // ---------- 복호화 ----------
  async function deriveKey(password, salt, iter) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password),
      "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
      base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  }
  async function decryptWith(key) {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(enc.iv) }, key, b64(enc.ct));
    return JSON.parse(new TextDecoder().decode(plain));
  }
  async function tryStoredKey() {
    const raw = store.get(KEY_STORE);
    if (!raw) return false;
    try {
      const s = JSON.parse(raw);
      if (s.salt !== enc.salt || s.iter !== enc.iter) return false;
      const key = await crypto.subtle.importKey("raw", b64(s.key), "AES-GCM", false, ["decrypt"]);
      data = await decryptWith(key);
      return true;
    } catch { store.del(KEY_STORE); return false; }
  }

  async function load() {
    try {
      const r = await fetch(`data/brief.enc?t=${Date.now()}`, { cache: "no-store" });
      if (!r.ok) throw new Error(r.status);
      enc = await r.json();
    } catch (e) {
      showLock("데이터를 불러오지 못했습니다. 잠시 후 다시 열어 주세요.");
      $("#unlockBtn").disabled = true;
      return;
    }
    if (await tryStoredKey()) render(); else showLock("");
  }

  function showLock(msg) {
    $("#app").hidden = true;
    $("#lock").hidden = false;
    $("#lockMsg").textContent = msg;
    $("#pw").focus();
  }

  $("#lockForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#unlockBtn");
    btn.disabled = true; btn.textContent = "여는 중…";
    $("#lockMsg").textContent = "";
    try {
      const key = await deriveKey($("#pw").value, b64(enc.salt), enc.iter);
      data = await decryptWith(key);
      if ($("#remember").checked) {
        const raw = await crypto.subtle.exportKey("raw", key);
        store.set(KEY_STORE, JSON.stringify({ salt: enc.salt, iter: enc.iter, key: b64e(raw) }));
      }
      $("#pw").value = "";
      render();
    } catch {
      $("#lockMsg").textContent = "비밀번호가 틀렸습니다.";
    } finally {
      btn.disabled = false; btn.textContent = "열기";
    }
  });
  $("#lockBtn").addEventListener("click", () => { store.del(KEY_STORE); data = null; showLock(""); });

  // ---------- 탭 ----------
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((x) => x.setAttribute("aria-selected", x === b));
    document.querySelectorAll(".tab").forEach((t) => { t.hidden = t.id !== `tab-${b.dataset.tab}`; });
    window.scrollTo({ top: 0 });
  }));

  // ---------- 렌더링 ----------
  function render() {
    $("#lock").hidden = true;
    $("#app").hidden = false;
    const m = data.meta;
    $("#asof").textContent = `데이터 기준 ${m.dataDate} · 생성 ${m.generatedAt.slice(0, 16).replace("T", " ")} · 단지 ${m.complexes}곳`;
    const ageH = (Date.now() - Date.parse(m.generatedAt)) / 36e5;
    const warns = [];
    if (ageH > STALE_HOURS) warns.push(`데이터가 ${Math.floor(ageH)}시간 전 것입니다. 마스터 PC 수집을 확인하세요.`);
    if (m.failed && m.failed.length) warns.push(`수집이 불완전한 단지: ${m.failed.join(", ")}`);
    $("#warn").hidden = !warns.length;
    $("#warn").textContent = warns.join(" ");
    renderToday();
    renderHot();
    renderChanges();
    renderMarket();
  }

  function renderToday() {
    const cur = store.get(POS_STORE) || "buyer";
    $("#positions").innerHTML = POSITIONS.map((p) =>
      `<button type="button" role="radio" aria-checked="${p.id === cur}" data-pos="${p.id}">${esc(p.label)}</button>`).join("");
    $("#positions").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
      store.set(POS_STORE, b.dataset.pos); renderToday();
    }));
    const acts = (data.actions && data.actions[cur]) || [];
    $("#actions").innerHTML = acts.map((a) => `<li>${esc(a)}</li>`).join("") ||
      `<li class="muted">오늘은 추천할 행동이 없습니다.</li>`;
    $("#summary").innerHTML = data.summary.map((s) => `
      <div class="card${s.scannedToday && s.complete ? "" : " stale"}">
        <h3>${esc(s.complex)}</h3>
        <div class="big">${s.active}<span class="muted small"> 건</span></div>
        <div class="muted small">매매 ${s.sale} · 전세 ${s.jeonse} · 월세 ${s.monthly}</div>
        <div class="row">
          <span class="tag-new">신규 ${s.new}</span>
          <span class="tag-drop">인하 ${s.drop}</span>
          <span class="tag-gone">사라짐 ${s.gone}</span>
        </div>
      </div>`).join("");
  }

  function itemHtml(u, opt = {}) {
    const ours = u.ours ? `<span class="badge-ours">우리</span>` : "";
    const floor = u.totalFloor ? `${u.floor}/${u.totalFloor}층` : `${u.floor || "-"}층`;
    const meta = [u.trade, u.supply && `${u.supply}㎡${u.pyeong ? ` (${u.pyeong}평)` : ""}`,
      u.dong && `${u.dong}동`, floor, u.direction, u.brokerCount && `중개사 ${u.brokerCount}`,
      u.daysOnMarket != null && `노출 ${u.daysOnMarket}일`].filter(Boolean).join(" · ");
    let price = esc(u.priceText || "");
    if (opt.change && u.oldText) {
      price = `<span class="old">${esc(u.oldText)}</span>${esc(u.newText)}` +
        (u.change ? `<span class="chg">${u.change > 0 ? "+" : "-"}${man(Math.abs(u.change))} (${pct(u.changePct)})</span>` : "");
    }
    if (opt.gone) price = esc(u.oldText || u.priceText || "");
    const reasons = (u.reasons || []).map((r) => `<span>${esc(r)}</span>`).join("");
    return `<article class="item${u.ours ? " ours" : ""}${opt.score ? "" : " noscore"}">
      ${opt.score ? `<div class="score" title="점수">${Math.round(u.score)}</div>` : ""}
      <div class="title">${esc(u.complex)}${ours}</div>
      <div class="price">${price}</div>
      <div class="meta">${esc(meta)}</div>
      ${reasons ? `<div class="reasons">${reasons}</div>` : ""}
      ${u.feature ? `<div class="feature">${esc(u.feature)}</div>` : ""}
    </article>`;
  }

  function fillSelect(sel, values, label) {
    const cur = sel.value;
    sel.innerHTML = `<option value="">${label}</option>` +
      values.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join("");
    if (values.includes(cur)) sel.value = cur;
  }

  function renderHot() {
    const hot = data.hot || [];
    fillSelect($("#fComplex"), [...new Set(hot.map((h) => h.complex))].sort(), "전체 단지");
    fillSelect($("#fSupply"), [...new Set(hot.map((h) => h.supply))].sort((a, b) => parseFloat(a) - parseFloat(b))
      .map(String), "전체 평형");
    const apply = () => {
      const c = $("#fComplex").value, s = $("#fSupply").value, o = $("#fOurs").value;
      const rows = hot.filter((h) => (!c || h.complex === c) && (!s || String(h.supply) === s) &&
        (!o || (o === "only" ? h.ours : !h.ours)));
      $("#hotList").innerHTML = rows.map((h) => itemHtml(h, { score: true })).join("") ||
        `<p class="empty">조건에 맞는 매물이 없습니다.</p>`;
    };
    ["#fComplex", "#fSupply", "#fOurs"].forEach((id) => { $(id).onchange = apply; });
    apply();
  }

  function renderChanges() {
    const sec = (list, el, n, opt) => {
      $(n).textContent = list.length ? `${list.length}건` : "";
      $(el).innerHTML = list.map((u) => itemHtml(u, opt)).join("") || `<p class="empty">없습니다.</p>`;
    };
    sec(data.drops || [], "#dropList", "#nDrop", { change: true });
    sec(data.new || [], "#newList", "#nNew", {});
    sec(data.gone || [], "#goneList", "#nGone", { gone: true });
    $("#riseWrap").hidden = !(data.rises && data.rises.length);
    if (data.rises && data.rises.length) sec(data.rises, "#riseList", "#nRise", { change: true });
  }

  function renderMarket() {
    // 주간 흐름: 활성 매물 수(선) + 신규·사라짐(막대)
    const t = data.trends || [];
    if (t.length < 2) {
      $("#trend").innerHTML = `<p class="empty">주간 추이는 기록이 2주 이상 쌓이면 표시됩니다.</p>`;
    } else {
      const W = 640, H = 220, L = 44, R = 16, T = 16, B = 28;
      const x = (i) => L + (i + 0.5) * (W - L - R) / t.length;
      const amax = Math.max(...t.map((d) => d.active)) * 1.1 || 1;
      const bmax = Math.max(1, ...t.map((d) => Math.max(d.new, d.gone)));
      const ya = (v) => T + (H - T - B) * (1 - v / amax);
      const yb = (v) => (H - B) - (H - T - B) * 0.45 * (v / bmax);
      const bw = Math.max(3, (W - L - R) / t.length / 3.5);
      const css = getComputedStyle(document.documentElement);
      const c = (n) => css.getPropertyValue(n).trim();
      let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="주간 매물 흐름">`;
      for (let k = 0; k <= 4; k++) {
        const v = amax * k / 4, y = ya(v);
        s += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" stroke="${c("--line")}"/>` +
          `<text x="${L - 6}" y="${y + 4}" font-size="11" text-anchor="end" fill="${c("--muted")}">${Math.round(v)}</text>`;
      }
      t.forEach((d, i) => {
        s += `<rect x="${x(i) - bw - 1}" y="${yb(d.new)}" width="${bw}" height="${H - B - yb(d.new)}" fill="${c("--good")}" opacity=".7"><title>${d.week} 신규 ${d.new}</title></rect>`;
        s += `<rect x="${x(i) + 1}" y="${yb(d.gone)}" width="${bw}" height="${H - B - yb(d.gone)}" fill="${c("--muted")}" opacity=".6"><title>${d.week} 사라짐 ${d.gone}</title></rect>`;
        if (i % Math.ceil(t.length / 8) === 0 || i === t.length - 1)
          s += `<text x="${x(i)}" y="${H - 8}" font-size="11" text-anchor="middle" fill="${c("--muted")}">${d.week.slice(5).replace("-", "/")}</text>`;
      });
      s += `<polyline fill="none" stroke="${c("--accent")}" stroke-width="2" points="${t.map((d, i) => `${x(i)},${ya(d.active)}`).join(" ")}"/>`;
      t.forEach((d, i) => { s += `<circle cx="${x(i)}" cy="${ya(d.active)}" r="3" fill="${c("--accent")}"><title>${d.week} 활성 ${d.active}</title></circle>`; });
      s += `</svg><div class="legend"><span><i style="background:${c("--accent")}"></i>활성 매물(주말 기준)</span>` +
        `<span><i style="background:${c("--good")}"></i>신규</span><span><i style="background:${c("--muted")}"></i>사라짐</span></div>`;
      $("#trend").innerHTML = s;
    }
    // 기준선 표
    const rows = data.baselines || [];
    let html = `<thead><tr><th>평형</th><th>거래</th><th>활성</th><th>최저 호가</th><th>호가 중앙값</th><th>기준선</th><th>거래권</th><th>거래권 매물</th></tr></thead><tbody>`;
    let last = null;
    rows.forEach((r) => {
      if (r.complex !== last) { html += `<tr class="group"><td colspan="8">${esc(r.complex)}</td></tr>`; last = r.complex; }
      html += `<tr><td>${esc(r.supply)}㎡</td><td>${esc(r.trade)}</td><td>${r.active}</td><td>${esc(r.minText)}</td>` +
        `<td>${esc(r.medianText)}</td><td>${esc(r.baselineText) || "-"}${r.baselineN ? ` <span class="muted">(${r.baselineN}건)</span>` : ""}</td>` +
        `<td>${esc(r.zoneText) || "-"}</td><td>${r.inZone || ""}</td></tr>`;
    });
    $("#baseTable").innerHTML = html + "</tbody>";
  }

  load();
})();
