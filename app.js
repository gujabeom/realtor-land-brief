/* 단지 브리핑 — data/brief.enc 를 비밀번호로 복호화해 보여준다.
 * 암호화 형식은 master/brief.py 와 같다: PBKDF2-SHA256 → AES-256-GCM.
 * '이 기기에서 기억'은 비밀번호가 아니라 도출된 키를 저장한다. */
(() => {
  "use strict";
  const KEY_STORE = "nlb.key.v1";
  const POS_STORE = "nlb.position";
  const GROUP_STORE = "nlb.group";
  const FILTER_STORE = "nlb.filter.v1";
  const BASEMODE_STORE = "nlb.basemode";
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
  let groupIds = null;   // 선택한 그룹의 단지번호 Set (null = 전체)
  // 필터: 거래방식·대표 평형(여러 개), 가격·월세 범위(만원)
  const TRADES = ["매매", "전세", "월세", "단기임대"];
  const PRICE_STEPS = [5000, 6000, 7000, 8000, 9000, 10000, 20000, 30000, 40000, 50000, 60000, 70000,
    80000, 90000, 100000, 110000, 120000, 130000, 140000, 150000, 160000, 170000, 180000, -180000];
  const RENT_STEPS = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, -200];   // 음수 = '~' (그 이상)
  let F = { trades: [], bands: [], pmin: null, pmax: null, rmin: null, rmax: null };
  const inGroupOnly = (x) => !groupIds || groupIds.has(x.complexId);
  const passBase = (x) => (!F.trades.length || F.trades.includes(x.trade)) &&
    (!F.bands.length || F.bands.includes(x.band));
  const passPrice = (x) => {
    const p = x.price ? x.price / 10000 : null, r = x.rent ? x.rent / 10000 : 0;
    if (F.pmin != null && (p == null || p < F.pmin)) return false;
    if (F.pmax != null && (p == null || p > F.pmax)) return false;
    if (F.rmin != null && r < F.rmin) return false;
    if (F.rmax != null && (!r || r > F.rmax)) return false;
    return true;
  };
  const inGroup = (x) => inGroupOnly(x) && passBase(x) && passPrice(x);
  const filterCount = () => (F.trades.length ? 1 : 0) + (F.bands.length ? 1 : 0) +
    (F.pmin != null || F.pmax != null ? 1 : 0) + (F.rmin != null || F.rmax != null ? 1 : 0);

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
    setupGroups();
    setupFilter();
    renderLists();
  }

  function renderLists() {
    renderToday();
    renderHot();
    renderChanges();
    renderMarket();
  }

  // 단지 그룹 (마스터 config/complexes.txt 의 '## 그룹명' 줄)
  function setupGroups() {
    const groups = data.groups || [];
    const sel = $("#fGroup");
    sel.hidden = !groups.length;
    sel.innerHTML = `<option value="">전체 단지</option>` +
      groups.map((g, i) => `<option value="${i}">${esc(g.name)}</option>`).join("");
    const saved = store.get(GROUP_STORE);
    const idx = groups.findIndex((g) => g.name === saved);
    sel.value = idx >= 0 ? String(idx) : "";
    const apply = () => {
      const g = groups[Number(sel.value)];
      groupIds = sel.value !== "" && g ? new Set(g.ids) : null;
    };
    apply();
    sel.onchange = () => {
      apply();
      if (sel.value === "") store.del(GROUP_STORE); else store.set(GROUP_STORE, groups[Number(sel.value)].name);
      renderLists();
    };
  }

  // ---------- 필터 패널 ----------
  const manText = (m) => {
    if (m == null) return "";
    const eok = Math.floor(m / 10000), rest = Math.round(m % 10000);
    return eok ? `${eok}억${rest ? ` ${rest.toLocaleString("ko-KR")}` : ""}` : `${rest.toLocaleString("ko-KR")}만`;
  };
  const stepLabel = (v, rent) => {
    const a = Math.abs(v);
    const t = rent ? (a >= 100 ? `${a / 100}백` : String(a)) : (a >= 10000 ? `${a / 10000}억` : `${a / 1000}천`);
    return v < 0 ? `${t}~` : t;
  };
  const parseMan = (txt) => {   // "3억", "3.5억", "3억 5000", "35000" → 만원
    const t = String(txt || "").replace(/[,\s]/g, "");
    if (!t) return null;
    const m = t.match(/^(?:(\d+(?:\.\d+)?)억)?(\d+(?:\.\d+)?)?(?:만|만원)?$/);
    if (!m || (!m[1] && !m[2])) return null;
    return Math.round((m[1] ? parseFloat(m[1]) * 10000 : 0) + (m[2] ? parseFloat(m[2]) : 0));
  };
  function saveFilter() { store.set(FILTER_STORE, JSON.stringify(F)); }
  function loadFilter() {
    try {
      const f = JSON.parse(store.get(FILTER_STORE) || "{}");
      F = { trades: (f.trades || []).filter((t) => TRADES.includes(t)),
        bands: (f.bands || []).filter((b) => (data.bands || []).includes(b)),
        pmin: f.pmin ?? null, pmax: f.pmax ?? null, rmin: f.rmin ?? null, rmax: f.rmax ?? null };
    } catch { /* 기본값 */ }
  }
  function stepClick(kind, v) {
    const lo = kind === "p" ? "pmin" : "rmin", hi = kind === "p" ? "pmax" : "rmax";
    if (v < 0) { F[lo] = -v; F[hi] = null; }
    else if (F[lo] == null || F[hi] != null) { F[lo] = v; F[hi] = null; }
    else if (v >= F[lo]) F[hi] = v;
    else { F[hi] = F[lo]; F[lo] = v; }
    filterChanged();
  }
  function drawFilter() {
    const chip = (vals, sel, key) => vals.map((v) =>
      `<button type="button" aria-pressed="${sel.includes(v)}" data-${key}="${esc(v)}">${esc(v)}</button>`).join("");
    $("#fpTrade").innerHTML = chip(TRADES, F.trades, "t");
    $("#fpBand").innerHTML = chip(data.bands || [], F.bands, "b");
    $("#fpTrade").querySelectorAll("button").forEach((b) => { b.onclick = () => toggle("trades", b.dataset.t); });
    $("#fpBand").querySelectorAll("button").forEach((b) => { b.onclick = () => toggle("bands", b.dataset.b); });
    const grid = (el, steps, rent, lo, hi) => {
      el.innerHTML = steps.map((v) => {
        const a = Math.abs(v);
        const edge = a === lo || a === hi;
        const on = lo != null && (hi != null ? a >= lo && a <= hi : (v < 0 ? a === lo : a === lo));
        return `<button type="button" class="${edge ? "edge" : on ? "on" : ""}" data-v="${v}">${stepLabel(v, rent)}</button>`;
      }).join("");
      el.querySelectorAll("button").forEach((b) => { b.onclick = () => stepClick(rent ? "r" : "p", Number(b.dataset.v)); });
    };
    grid($("#fpPriceGrid"), PRICE_STEPS, false, F.pmin, F.pmax);
    grid($("#fpRentGrid"), RENT_STEPS, true, F.rmin, F.rmax);
    $("#fpPmin").value = F.pmin != null ? manText(F.pmin) : "";
    $("#fpPmax").value = F.pmax != null ? manText(F.pmax) : "";
    $("#fpRmin").value = F.rmin ?? "";
    $("#fpRmax").value = F.rmax ?? "";
    // 요약 줄 · 배지
    const n = filterCount();
    $("#filterCount").hidden = !n;
    $("#filterCount").textContent = n;
    $("#filterBtn").classList.toggle("active", n > 0);
    const parts = [];
    if (F.trades.length) parts.push(F.trades.join("·"));
    if (F.bands.length) parts.push(F.bands.join("·"));
    if (F.pmin != null || F.pmax != null) parts.push(`${manText(F.pmin) || "0"} ~ ${manText(F.pmax) || ""}`.trim());
    if (F.rmin != null || F.rmax != null) parts.push(`월세 ${F.rmin ?? 0} ~ ${F.rmax ?? ""}`.trim());
    $("#filterSummary").hidden = !parts.length;
    $("#filterSummary").innerHTML = parts.map((p) => `<span>${esc(p)}</span>`).join("") +
      (parts.length ? `<button type="button" id="fsClear">조건 삭제</button>` : "");
    const c = $("#fsClear");
    if (c) c.onclick = resetFilter;
  }
  function toggle(key, v) {
    F[key] = F[key].includes(v) ? F[key].filter((x) => x !== v) : F[key].concat(v);
    filterChanged();
  }
  function resetFilter() {
    F = { trades: [], bands: [], pmin: null, pmax: null, rmin: null, rmax: null };
    filterChanged();
  }
  function filterChanged() { saveFilter(); drawFilter(); renderLists(); }
  function setupFilter() {
    loadFilter();
    const open = (on) => {
      $("#filterPanel").hidden = !on;
      $("#filterBtn").setAttribute("aria-expanded", on);
      if (on) $("#filterPanel").scrollIntoView({ block: "nearest" });
    };
    $("#filterBtn").onclick = () => open($("#filterPanel").hidden);
    $("#fpClose").onclick = () => open(false);
    $("#fpReset").onclick = resetFilter;
    const inp = (id, key, parse) => {
      $(id).onchange = () => { F[key] = parse($(id).value); filterChanged(); };
    };
    inp("#fpPmin", "pmin", parseMan);
    inp("#fpPmax", "pmax", parseMan);
    inp("#fpRmin", "rmin", (t) => (String(t).trim() === "" ? null : Math.max(0, parseInt(t, 10) || 0)));
    inp("#fpRmax", "rmax", (t) => (String(t).trim() === "" ? null : Math.max(0, parseInt(t, 10) || 0)));
    drawFilter();
  }

  // ---------- 추천 행동 (필터된 데이터로 브라우저에서 계산) ----------
  function buildActions(v) {
    const out = { buyer: [], hunter: [], seller: [], market: [] };
    const nNew = v.news.length, nDrop = v.drops.length, nGone = v.gone.length;
    if (nNew) {
      const cnt = {};
      v.news.forEach((u) => { cnt[u.complex] = (cnt[u.complex] || 0) + 1; });
      const [bn, bc] = Object.entries(cnt).sort((a, b) => b[1] - a[1])[0];
      out.buyer.push(`어제 신규 ${nNew}건. ${bn}에서 ${bc}건으로 가장 많습니다.`);
    }
    v.baselines.filter((b) => b.inZone).slice(0, 3).forEach((b) =>
      out.buyer.push(`${b.complex} ${b.supply}㎡ ${b.trade}: 거래권(${b.zoneText}) 매물 ${b.inZone}건을 먼저 안내하세요.`));
    if (!out.buyer.length) out.buyer.push("신규 매물이 없습니다. '급매' 탭 상위 매물로 상담을 준비하세요.");
    if (nDrop) out.hunter.push(`어제 가격 인하 ${nDrop}건. '변동' 탭에서 인하 폭이 큰 순서로 확인하세요.`);
    const top = v.hot[0];
    if (top) out.hunter.push(`점수 1위: ${top.complex} ${top.supply}㎡ ${top.dong}동 ${top.floor}층 ${top.priceText} — ${(top.reasons || []).slice(0, 3).join(", ")}`);
    if (!out.hunter.length) out.hunter.push("이 조건에서는 눈에 띄는 급매 신호가 없습니다.");
    if (nGone) out.seller.push(`어제 사라진 매물 ${nGone}건(거래 추정). 마지막 호가를 매도 상담 근거로 쓰세요.`);
    const withBase = v.baselines.filter((b) => b.baseline);
    withBase.slice(0, 3).forEach((b) => out.seller.push(
      `${b.complex} ${b.supply}㎡ ${b.trade}: 추정 거래가 ${b.baselineText}, 최저 호가 ${b.minText}, 경쟁 매물 ${b.active}건.`));
    if (!withBase.length) out.seller.push("추정 거래가(기준선)는 사라진 매물이 쌓이면 표시됩니다. 지금은 최저 호가와 경쟁 매물 수를 근거로 쓰세요.");
    out.market.push(`단지 ${v.cards.length}곳, 매물 ${v.cards.reduce((a, c) => a + c.active, 0)}건 (신규 ${nNew} · 인하 ${nDrop} · 사라짐 ${nGone}).`);
    const tr = v.trends;
    if (tr.length >= 2 && tr[tr.length - 2].active) {
      const d = tr[tr.length - 1].active - tr[tr.length - 2].active;
      out.market.push(`지난주 대비 매물 ${d > 0 ? "+" : ""}${d}건 (${pct(d / tr[tr.length - 2].active)}).`);
    }
    return out;
  }

  function renderToday() {
    const cur = store.get(POS_STORE) || "buyer";
    $("#positions").innerHTML = POSITIONS.map((p) =>
      `<button type="button" role="radio" aria-checked="${p.id === cur}" data-pos="${p.id}">${esc(p.label)}</button>`).join("");
    $("#positions").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
      store.set(POS_STORE, b.dataset.pos); renderToday();
    }));
    // 단지별 카드: 활성 매물(units) · 어제 변동을 필터 조건으로 집계
    const units = (data.units || []).map((r) => ({ complexId: r[0], trade: r[1], band: r[2], price: r[3], rent: r[4] }))
      .filter(inGroup);
    const news = (data.new || []).filter(inGroup), drops = (data.drops || []).filter(inGroup),
      gone = (data.gone || []).filter(inGroup);
    const filtered = filterCount() > 0;
    const cards = data.summary.filter(inGroupOnly).map((s) => {
      const us = units.filter((u) => u.complexId === s.complexId);
      const c = (list) => list.filter((u) => u.complexId === s.complexId).length;
      return { ...s, active: us.length, sale: us.filter((u) => u.trade === "매매").length,
        jeonse: us.filter((u) => u.trade === "전세").length,
        monthly: us.filter((u) => u.trade === "월세" || u.trade === "단기임대").length,
        new: c(news), drop: c(drops), gone: c(gone) };
    }).filter((s) => !filtered || s.active || s.new || s.drop || s.gone);
    const acts = buildActions({ cards, news, drops, gone, hot: (data.hot || []).filter(inGroup),
      baselines: (data.baselines || []).filter((b) => inGroupOnly(b) && passBase(b)),
      trends: !groupIds && !filtered ? (data.trends || []) : [] })[cur] || [];
    $("#actions").innerHTML = acts.map((a) => `<li>${esc(a)}</li>`).join("") ||
      `<li class="muted">오늘은 추천할 행동이 없습니다.</li>`;
    $("#summaryNote").textContent = filtered ? "필터 조건 기준 · 어제 대비" : "어제 대비";
    $("#summary").innerHTML = (cards.map((s) => `
      <div class="card${s.scannedToday && s.complete ? "" : " stale"}">
        <h3>${esc(s.complex)}</h3>
        <div class="big">${s.active}<span class="muted small"> 건</span></div>
        <div class="muted small">매매 ${s.sale} · 전세 ${s.jeonse} · 월세 ${s.monthly}</div>
        <div class="row">
          <span class="tag-new">신규 ${s.new}</span>
          <span class="tag-drop">인하 ${s.drop}</span>
          <span class="tag-gone">사라짐 ${s.gone}</span>
        </div>
      </div>`).join("")) || `<p class="empty">이 조건의 매물이 없습니다.</p>`;
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
    const hot = (data.hot || []).filter(inGroup);
    // 단지 순서 = 마스터의 config/complexes.txt 순서 (complexOrder)
    const order = (data.complexOrder || []).map((c) => c.name);
    const present = new Set(hot.map((h) => h.complex));
    const names = order.filter((n) => present.has(n)).concat([...present].filter((n) => !order.includes(n)));
    fillSelect($("#fComplex"), names, "전체 단지");
    fillSelect($("#fSupply"), [...new Set(hot.map((h) => h.supply))].sort((a, b) => parseFloat(a) - parseFloat(b) || String(a).localeCompare(String(b)))
      .map(String), "세부 평형 전체");
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
    const rises = (data.rises || []).filter(inGroup);
    sec((data.drops || []).filter(inGroup), "#dropList", "#nDrop", { change: true });
    sec((data.new || []).filter(inGroup), "#newList", "#nNew", {});
    sec((data.gone || []).filter(inGroup), "#goneList", "#nGone", { gone: true });
    $("#riseWrap").hidden = !rises.length;
    if (rises.length) sec(rises, "#riseList", "#nRise", { change: true });
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
    const mode = store.get(BASEMODE_STORE) === "band" ? "band" : "supply";
    document.querySelectorAll("#baseMode button").forEach((b) => {
      b.setAttribute("aria-checked", b.dataset.mode === mode);
      b.onclick = () => { store.set(BASEMODE_STORE, b.dataset.mode); renderMarket(); };
    });
    const rows = ((mode === "band" ? data.baselinesByBand : data.baselines) || []).filter((b) => inGroupOnly(b) && passBase(b));
    $("#baseNote").hidden = !(F.pmin != null || F.pmax != null || F.rmin != null || F.rmax != null);
    let html = `<thead><tr><th>${mode === "band" ? "대표 평형" : "평형"}</th><th>거래</th><th>활성</th><th>최저 호가</th><th>호가 중앙값</th><th>기준선</th><th>거래권</th><th>거래권 매물</th></tr></thead><tbody>`;
    let last = null;
    rows.forEach((r) => {
      if (r.complex !== last) { html += `<tr class="group"><td colspan="8">${esc(r.complex)}</td></tr>`; last = r.complex; }
      const label = mode === "band"
        ? `${esc(r.band)} <span class="muted">${esc((r.supplies || []).join("·"))}</span>`
        : `${esc(r.supply)}㎡ <span class="muted">${esc(r.band || "")}</span>`;
      html += `<tr><td>${label}</td><td>${esc(r.trade)}</td><td>${r.active}</td><td>${esc(r.minText)}</td>` +
        `<td>${esc(r.medianText)}</td><td>${esc(r.baselineText) || "-"}${r.baselineN ? ` <span class="muted">(${r.baselineN}건)</span>` : ""}</td>` +
        `<td>${esc(r.zoneText) || "-"}</td><td>${r.inZone || ""}</td></tr>`;
    });
    $("#baseTable").innerHTML = rows.length ? html + "</tbody>" : `<tbody><tr><td class="empty">이 조건의 매물이 없습니다.</td></tr></tbody>`;
  }

  load();
})();
